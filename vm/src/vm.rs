// vm.rs ---

// Copyright (C) 2022 Hussein Ait-Lahcen

// Author: Hussein Ait-Lahcen <hussein.aitlahcen@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the sale,
// use or other dealings in this Software without prior written authorization.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::{
    executor::{CosmwasmQueryResult, QueryResult},
    input::Input,
};
use alloc::{string::String, vec::Vec};
use core::fmt::Debug;
#[cfg(feature = "stargate")]
use cosmwasm_minimal_std::ibc::IbcTimeout;
#[cfg(feature = "iterator")]
use cosmwasm_minimal_std::Order;
use cosmwasm_minimal_std::{Binary, Coin, ContractInfoResponse, Event, SystemResult};

use serde::de::DeserializeOwned;

/// Gas checkpoint, used to meter sub-call gas usage.
pub enum VmGasCheckpoint {
    /// Unlimited gas in a sub-call, the sub-call might exhaust the parent gas.
    Unlimited,
    /// Limited gas with fixed amount, the sub-call will only be able to execute under this gas limit.
    Limited(u64),
}

/// Gasable VM calls.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VmGas {
    /// Instrumentation gas raised by the injected code.
    Instrumentation { metered: u32 },
    /// Cost of `set_contract_meta`.
    SetContractMeta,
    /// Cost of `contract_meta`.
    GetContractMeta,
    /// Cost of `query_continuation`.
    QueryContinuation,
    /// Cost of `continue_execute`.
    ContinueExecute { nb_of_coins: u32 },
    /// Cost of `continue_instantiate`.
    ContinueInstantiate { nb_of_coins: u32 },
    /// Cost of `continue_migrate`.
    ContinueMigrate,
    /// Cost of `query_custom`.
    QueryCustom,
    /// Cost of `message_custom`.
    MessageCustom,
    /// Cost of `query_raw`.
    QueryRaw,
    /// Cost of `transfer`.
    Transfer { nb_of_coins: u32 },
    /// Cost of `burn`.
    Burn,
    /// Cost of `balance`.
    Balance,
    /// Cost of `all_balance`.
    AllBalance,
    /// Cost of `query_info`.
    QueryInfo,
    /// Cost of `db_read`.
    DbRead,
    /// Cost of `db_write`.
    DbWrite,
    /// Cost of `db_remove`.
    DbRemove,
    #[cfg(feature = "iterator")]
    /// Cost of `db_scan`.
    DbScan,
    #[cfg(feature = "iterator")]
    /// Cost of `db_next`.
    DbNext,
    /// Cost of `debug`
    Debug,
    /// Cost of `secp256k1_verify`
    Secp256k1Verify,
    /// Cost of `secp256k1_recover_pubkey`
    Secp256k1RecoverPubkey,
    /// Cost of `ed25519_verify`
    Ed25519Verify,
    /// Cost of `ed25519_batch_verify`
    Ed25519BatchVerify,
    /// Cost of `addr_validate`
    AddrValidate,
    /// Cost of `addr_canonicalize`
    AddrCanonicalize,
    /// Cost of `addr_humanize`
    AddrHumanize,
    #[cfg(feature = "stargate")]
    /// Cost of `ibc_transfer`.
    IbcTransfer,
    #[cfg(feature = "stargate")]
    /// Cost of `ibc_send_packet`.
    IbcSendPacket,
    #[cfg(feature = "stargate")]
    /// Cost of `ibc_close_channel`.
    IbcCloseChannel,
}

pub type VmInputOf<'a, T> = <T as VMBase>::Input<'a>;
pub type VmOutputOf<'a, T> = <T as VMBase>::Output<'a>;
pub type VmErrorOf<T> = <T as VMBase>::Error;
pub type VmQueryCustomOf<T> = <T as VMBase>::QueryCustom;
pub type VmMessageCustomOf<T> = <T as VMBase>::MessageCustom;
pub type VmAddressOf<T> = <T as VMBase>::Address;
pub type VmCanonicalAddressOf<T> = <T as VMBase>::CanonicalAddress;
pub type VmStorageKeyOf<T> = <T as VMBase>::StorageKey;
pub type VmStorageValueOf<T> = <T as VMBase>::StorageValue;
pub type VmContracMetaOf<T> = <T as VMBase>::ContractMeta;

/// A way of calling a VM. From the abstract `call` to `raw_call`.
pub trait VM: VMBase {
    /// Execute an abstract call against the VM.
    fn call<'a, I>(&mut self, input: I) -> Result<I::Output, Self::Error>
    where
        I: Input + TryInto<VmInputOf<'a, Self>, Error = Self::Error>,
        I::Output: for<'x> TryFrom<VmOutputOf<'x, Self>, Error = Self::Error>,
    {
        let input = input.try_into()?;
        self.raw_call::<I::Output>(input)
    }

    /// Execute a raw call against the VM.
    fn raw_call<'a, O>(&mut self, input: Self::Input<'a>) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::Output<'x>, Error = Self::Error>;
}

/// Base functions required to be implemented by a VM to run CosmWasm contracts.
pub trait VMBase {
    /// Input type, abstract type representing function inputs.
    type Input<'a>;
    /// Output type, abstract type representing function outputs.
    type Output<'a>;
    /// Custom query, also known as chain extension.
    type QueryCustom: DeserializeOwned + Debug;
    /// Custom message, also known as chain extension.
    type MessageCustom: DeserializeOwned + Debug;
    /// Metadata of a contract.
    type ContractMeta;
    /// Unique identifier for contract instances and users under the system.
    type Address;
    /// Binary representation of `Address`.
    type CanonicalAddress;
    /// Type of key used by the underlying DB.
    type StorageKey;
    /// Type of value used by the underlying DB.
    type StorageValue;
    /// Possible errors raised by this VM.
    type Error;

    /// Get the contract metadata of the currently running contract.
    fn running_contract_meta(&mut self) -> Result<Self::ContractMeta, Self::Error>;

    #[cfg(feature = "iterator")]
    /// Allows iteration over a set of key/value pairs, either forwards or backwards.
    /// Returns an iterator ID that is unique within the Storage instance.
    fn db_scan(
        &mut self,
        start: Option<Self::StorageKey>,
        end: Option<Self::StorageKey>,
        order: Order,
    ) -> Result<u32, Self::Error>;

    #[cfg(feature = "iterator")]
    /// Returns the next element of the iterator with the given ID.
    fn db_next(
        &mut self,
        iterator_id: u32,
    ) -> Result<(Self::StorageKey, Self::StorageValue), Self::Error>;

    /// Change the contract meta of a contract, actually migrating it.
    fn set_contract_meta(
        &mut self,
        address: Self::Address,
        new_contract_meta: Self::ContractMeta,
    ) -> Result<(), Self::Error>;

    /// Get the contract metadata of a given contract.
    fn contract_meta(&mut self, address: Self::Address) -> Result<Self::ContractMeta, Self::Error>;

    /// Continue execution by calling query at the given contract address.
    fn query_continuation(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<QueryResult, Self::Error>;

    /// Continue execution by calling execute at the given contract address.
    /// Implementor must ensure that the funds are moved before executing the contract.
    fn continue_execute(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error>;

    /// Continue execution by instantiating the given contract code_id.
    /// Implementor must ensure that the funds are moved before executing the contract.
    fn continue_instantiate(
        &mut self,
        contract_meta: Self::ContractMeta,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<(Self::Address, Option<Binary>), Self::Error>;

    /// Continue execution by calling migrate at the given contract address.
    /// Implementor must ensure that the funds are moved before executing the contract.
    fn continue_migrate(
        &mut self,
        address: Self::Address,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error>;

    /// Custom CosmWasm query. Usually a host extension.
    fn query_custom(
        &mut self,
        query: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, Self::Error>;

    /// Custom CosmWasm message. Usually a host extension.
    fn message_custom(
        &mut self,
        message: Self::MessageCustom,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error>;

    /// Query raw value in a contract db.
    fn query_raw(
        &mut self,
        address: Self::Address,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error>;

    /// Transfer `funds` from the current bank to `to`.
    fn transfer(&mut self, to: &Self::Address, funds: &[Coin]) -> Result<(), Self::Error>;

    /// Burn the `funds` from the current contract.
    fn burn(&mut self, funds: &[Coin]) -> Result<(), Self::Error>;
    /// Query the balance of `denom` tokens.
    fn balance(&mut self, account: &Self::Address, denom: String) -> Result<Coin, Self::Error>;

    /// Query for the balance of all tokens.
    fn all_balance(&mut self, account: &Self::Address) -> Result<Vec<Coin>, Self::Error>;

    /// Query the contract info.
    fn query_info(&mut self, address: Self::Address) -> Result<ContractInfoResponse, Self::Error>;

    /// Log the message
    fn debug(&mut self, message: Vec<u8>) -> Result<(), Self::Error>;

    /// Read an entry from the current contract db.
    fn db_read(&mut self, key: Self::StorageKey)
        -> Result<Option<Self::StorageValue>, Self::Error>;

    /// Write into the current contract db.
    fn db_write(
        &mut self,
        key: Self::StorageKey,
        value: Self::StorageValue,
    ) -> Result<(), Self::Error>;

    /// Remove an entry from the current contract db.
    fn db_remove(&mut self, key: Self::StorageKey) -> Result<(), Self::Error>;

    /// Validates a human readable address.
    /// NOTE: The return type is `Result<Result<(), Self::Error>, Self::Error>` but not
    /// `Result<(), Self::Error>`, this is because errors that are related to address
    /// validation are treated differently in wasmi vm. Any errors that are related to
    /// address validation should be returned in the inner result like `Ok(Err(..))`.
    fn addr_validate(&mut self, input: &str) -> Result<Result<(), Self::Error>, Self::Error>;

    /// Returns a canonical address from a human readable address.
    /// see: [`Self::addr_validate`]
    fn addr_canonicalize(
        &mut self,
        input: &str,
    ) -> Result<Result<Self::CanonicalAddress, Self::Error>, Self::Error>;

    /// Returns a human readable address from a canonical address.
    fn addr_humanize(
        &mut self,
        addr: &Self::CanonicalAddress,
    ) -> Result<Result<Self::Address, Self::Error>, Self::Error>;

    /// Abort execution, called when the contract panic.
    fn abort(&mut self, message: String) -> Result<(), Self::Error>;

    /// Charge gas value.
    fn charge(&mut self, value: VmGas) -> Result<(), Self::Error>;

    /// Push a gas checkpoint, used to trap once the checkpoint is reached.
    fn gas_checkpoint_push(&mut self, checkpoint: VmGasCheckpoint) -> Result<(), Self::Error>;

    /// Pop a previously pushed gas checkpoint.
    fn gas_checkpoint_pop(&mut self) -> Result<(), Self::Error>;

    /// Ensure that some gas is available.
    fn gas_ensure_available(&mut self) -> Result<(), Self::Error>;

    /// Verifies `message_hash` against a `signature` with a `public_key`, using the
    /// secp256k1 ECDSA parametrization.
    fn secp256k1_verify(
        &mut self,
        message_hash: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Self::Error>;

    /// Recovers a public key from a message hash and a signature.
    ///
    /// Returns the recovered pubkey in compressed form, which can be used
    /// in secp256k1_verify directly. Any errors related to recovering the
    /// public key should result in `Ok(Err(()))`
    fn secp256k1_recover_pubkey(
        &mut self,
        message_hash: &[u8],
        signature: &[u8],
        recovery_param: u8,
    ) -> Result<Result<Vec<u8>, ()>, Self::Error>;

    /// Verify `message` against a `signature`, with the `public_key` of the signer, using
    /// the ed25519 elliptic curve digital signature parametrization / algorithm.
    fn ed25519_verify(
        &mut self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Self::Error>;

    /// Performs batch Ed25519 signature verification.
    fn ed25519_batch_verify(
        &mut self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<bool, Self::Error>;

    #[cfg(feature = "stargate")]
    /// Transfer tokens over IBC.
    fn ibc_transfer(
        &mut self,
        channel_id: String,
        to_address: String,
        amount: Coin,
        timeout: IbcTimeout,
    ) -> Result<(), Self::Error>;

    #[cfg(feature = "stargate")]
    /// Send a packet over IBC.
    fn ibc_send_packet(
        &mut self,
        channel_id: String,
        data: Binary,
        timeout: IbcTimeout,
    ) -> Result<(), Self::Error>;

    #[cfg(feature = "stargate")]
    /// Close an IBC channel.
    fn ibc_close_channel(&mut self, channel_id: String) -> Result<(), Self::Error>;
}
