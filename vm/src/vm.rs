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

use crate::input::Input;
use alloc::{string::String, vec::Vec};
use core::fmt::Debug;
use cosmwasm_minimal_std::{
    Binary, Coin, ContractInfoResponse, CosmwasmQueryResult, Event, QueryResult, SystemResult,
};
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
    /// Cost of calling `raw_call`.
    RawCall,
    /// Cost of `set_contract_meta`.
    SetContractMeta,
    /// Cost of `contract_meta`.
    GetContractMeta,
    /// Cost of `query_continuation`.
    QueryContinuation,
    /// Cost of `continue_execute`.
    ContinueExecute,
    /// Cost of `continue_instantiate`.
    ContinueInstantiate,
    /// Cost of `continue_migrate`.
    ContinueMigrate,
    /// Cost of `query_custom`.
    QueryCustom,
    /// Cost of `message_custom`.
    MessageCustom,
    /// Cost of `query_raw`.
    QueryRaw,
    /// Cost of `transfer`.
    Transfer,
    /// Cost of `burn`.
    Burn,
    /// Cost of `balance`.
    Balance,
    /// Cost of `all_balance`.
    AllBalance,
    /// Cost of `query_info`.
    QueryInfo,
    /// Cost of `query_chain`.
    QueryChain,
    /// Cost of `db_read`.
    DbRead,
    /// Cost of `db_write`.
    DbWrite,
    /// Cost of `db_remove`.
    DbRemove,
}

pub type VmInputOf<'a, T> = <T as VMBase>::Input<'a>;
pub type VmOutputOf<'a, T> = <T as VMBase>::Output<'a>;
pub type VmErrorOf<T> = <T as VMBase>::Error;
pub type VmQueryCustomOf<T> = <T as VMBase>::QueryCustom;
pub type VmMessageCustomOf<T> = <T as VMBase>::MessageCustom;
pub type VmAddressOf<T> = <T as VMBase>::Address;
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
    /// Type of key used by the underlying DB.
    type StorageKey;
    /// Type of value used by the underlying DB.
    type StorageValue;
    /// Possible errors raised by this VM.
    type Error;

    // Get the contract metadata of the currently running contract.
    fn running_contract_meta(&mut self) -> Self::ContractMeta;

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
}
