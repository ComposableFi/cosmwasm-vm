use crate::{
    WasmiContext, WasmiFunctionName, WasmiFunctionParams, WasmiFunctionResult, WasmiInput,
    WasmiModule, WasmiOutput, WasmiVMError,
};
use alloc::{string::String, vec::Vec};
use core::{
    fmt::{Debug, Display},
    marker::PhantomData,
};
#[cfg(feature = "cosmwasm_1_2")]
use cosmwasm_std::CodeInfoResponse;
#[cfg(feature = "iterator")]
use cosmwasm_std::Order;
use cosmwasm_std::{
    Addr, Binary, CanonicalAddr, Coin, ContractInfoResponse, Env, Event, MessageInfo, Reply,
    SystemResult,
};
#[cfg(feature = "cosmwasm_1_2")]
use cosmwasm_vm::system::CosmwasmCodeId;
use cosmwasm_vm::{
    executor::{CosmwasmQueryResult, ExecutorError, QueryResult},
    has::Has,
    memory::{MemoryReadError, MemoryWriteError, Pointable, ReadableMemory, WritableMemory},
    system::{CosmwasmContractMeta, SystemError},
    transaction::{Transactional, TransactionalErrorOf},
    vm::{
        VMBase, VmAddressOf, VmCanonicalAddressOf, VmContracMetaOf, VmErrorOf, VmGas,
        VmGasCheckpoint, VmMessageCustomOf, VmQueryCustomOf, VmStorageKeyOf, VmStorageValueOf, VM,
    },
};
use wasmi::{AsContextMut, Extern, Store};

/// Base traits that are needed to be implemented to work with `WasmiVM`.
pub trait WasmiBaseVM = Sized
    + VMBase<
        ContractMeta = CosmwasmContractMeta<VmAddressOf<Self>>,
        StorageKey = Vec<u8>,
        StorageValue = Vec<u8>,
    > + WasmiContext
    + Transactional
    + Has<Env>
    + Has<MessageInfo>
where
    VmAddressOf<Self>: Clone + TryFrom<String, Error = VmErrorOf<Self>> + Into<Addr>,
    VmCanonicalAddressOf<Self>:
        Clone + TryFrom<Vec<u8>, Error = VmErrorOf<Self>> + Into<CanonicalAddr>,
    VmErrorOf<Self>: From<wasmi::Error>
        + From<WasmiVMError>
        + From<MemoryReadError>
        + From<MemoryWriteError>
        + From<ExecutorError>
        + From<SystemError>
        + From<TransactionalErrorOf<Self>>
        + wasmi::core::HostError
        + Debug
        + Display;

/// `WasmiVM` that owns the execution and the underlying VM.
pub type OwnedWasmiVM<V> = WasmiVM<V, Store<V>>;

/// Generic `WasmiVM` that handles wasm function calls, memory operations, charging gas, etc.
/// It handles the outer logic and forwards the execution to the underlying VM for VM
/// specific behavior.
pub struct WasmiVM<V: WasmiBaseVM, S: AsContextMut<UserState = V>>(pub S);

impl<V: WasmiBaseVM, S: AsContextMut<UserState = V>> WasmiVM<V, S> {
    pub fn new(store: S) -> Self {
        WasmiVM(store)
    }
}

/// Base VM implementation which basically, charges for gas and forwards
/// the execution to the underlying VM.
impl<V, S> VMBase for WasmiVM<V, S>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Input<'x> = WasmiInput<Self>;
    type Output<'x> = WasmiOutput<Self>;
    type QueryCustom = VmQueryCustomOf<V>;
    type MessageCustom = VmMessageCustomOf<V>;
    type ContractMeta = VmContracMetaOf<V>;
    type Address = VmAddressOf<V>;
    type CanonicalAddress = VmCanonicalAddressOf<V>;
    type StorageKey = VmStorageKeyOf<V>;
    type StorageValue = VmStorageValueOf<V>;
    type Error = VmErrorOf<V>;

    fn running_contract_meta(&mut self) -> Result<Self::ContractMeta, Self::Error> {
        self.charge(VmGas::GetContractMeta)?;
        self.0.as_context_mut().data_mut().running_contract_meta()
    }

    #[cfg(feature = "iterator")]
    fn db_scan(
        &mut self,
        start: Option<Self::StorageKey>,
        end: Option<Self::StorageKey>,
        order: Order,
    ) -> Result<u32, Self::Error> {
        self.charge(VmGas::DbScan)?;
        self.0
            .as_context_mut()
            .data_mut()
            .db_scan(start, end, order)
    }

    #[cfg(feature = "iterator")]
    fn db_next(
        &mut self,
        iterator_id: u32,
    ) -> Result<(Self::StorageKey, Self::StorageValue), Self::Error> {
        self.charge(VmGas::DbNext)?;
        self.0.as_context_mut().data_mut().db_next(iterator_id)
    }

    fn set_contract_meta(
        &mut self,
        address: Self::Address,
        new_contract_meta: Self::ContractMeta,
    ) -> Result<(), Self::Error> {
        self.charge(VmGas::SetContractMeta)?;
        self.0
            .as_context_mut()
            .data_mut()
            .set_contract_meta(address, new_contract_meta)
    }

    fn contract_meta(&mut self, address: Self::Address) -> Result<Self::ContractMeta, Self::Error> {
        self.charge(VmGas::GetContractMeta)?;
        self.0.as_context_mut().data_mut().contract_meta(address)
    }

    fn continue_query(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<QueryResult, Self::Error> {
        self.charge(VmGas::ContinueQuery)?;
        self.0
            .as_context_mut()
            .data_mut()
            .continue_query(address, message)
    }

    fn continue_execute(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.charge(VmGas::ContinueExecute {
            nb_of_coins: u32::try_from(funds.len()).map_err(|_| WasmiVMError::MaxLimitExceeded)?,
        })?;
        self.0
            .as_context_mut()
            .data_mut()
            .continue_execute(address, funds, message, event_handler)
    }

    fn continue_instantiate(
        &mut self,
        contract_meta: Self::ContractMeta,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<(Self::Address, Option<Binary>), Self::Error> {
        self.charge(VmGas::ContinueInstantiate {
            nb_of_coins: u32::try_from(funds.len()).map_err(|_| WasmiVMError::MaxLimitExceeded)?,
        })?;
        self.0.as_context_mut().data_mut().continue_instantiate(
            contract_meta,
            funds,
            message,
            event_handler,
        )
    }

    #[cfg(feature = "cosmwasm_1_2")]
    fn continue_instantiate2(
        &mut self,
        contract_meta: Self::ContractMeta,
        funds: Vec<Coin>,
        salt: &[u8],
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<(Self::Address, Option<Binary>), Self::Error> {
        self.charge(VmGas::ContinueInstantiate2 {
            nb_of_coins: u32::try_from(funds.len()).map_err(|_| WasmiVMError::MaxLimitExceeded)?,
        })?;
        self.0.as_context_mut().data_mut().continue_instantiate2(
            contract_meta,
            funds,
            salt,
            message,
            event_handler,
        )
    }

    fn continue_migrate(
        &mut self,
        address: Self::Address,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.charge(VmGas::ContinueMigrate)?;
        self.0
            .as_context_mut()
            .data_mut()
            .continue_migrate(address, message, event_handler)
    }

    fn continue_reply(
        &mut self,
        message: Reply,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.charge(VmGas::ContinueReply)?;
        self.0
            .as_context_mut()
            .data_mut()
            .continue_reply(message, event_handler)
    }

    fn query_custom(
        &mut self,
        query: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, Self::Error> {
        self.charge(VmGas::QueryCustom)?;
        self.0.as_context_mut().data_mut().query_custom(query)
    }

    fn message_custom(
        &mut self,
        message: Self::MessageCustom,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.charge(VmGas::MessageCustom)?;
        self.0
            .as_context_mut()
            .data_mut()
            .message_custom(message, event_handler)
    }

    fn query_raw(
        &mut self,
        address: Self::Address,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error> {
        self.charge(VmGas::QueryRaw)?;
        self.0.as_context_mut().data_mut().query_raw(address, key)
    }

    fn transfer_from(
        &mut self,
        from: &Self::Address,
        to: &Self::Address,
        funds: &[Coin],
    ) -> Result<(), Self::Error> {
        self.charge(VmGas::Transfer {
            nb_of_coins: u32::try_from(funds.len()).map_err(|_| WasmiVMError::MaxLimitExceeded)?,
        })?;
        self.0
            .as_context_mut()
            .data_mut()
            .transfer_from(from, to, funds)
    }

    fn transfer(&mut self, to: &Self::Address, funds: &[Coin]) -> Result<(), Self::Error> {
        self.charge(VmGas::Transfer {
            nb_of_coins: u32::try_from(funds.len()).map_err(|_| WasmiVMError::MaxLimitExceeded)?,
        })?;
        self.0.as_context_mut().data_mut().transfer(to, funds)
    }

    fn burn(&mut self, funds: &[Coin]) -> Result<(), Self::Error> {
        self.charge(VmGas::Burn)?;
        self.0.as_context_mut().data_mut().burn(funds)
    }

    fn balance(&mut self, account: &Self::Address, denom: String) -> Result<Coin, Self::Error> {
        self.charge(VmGas::Balance)?;
        self.0.as_context_mut().data_mut().balance(account, denom)
    }

    fn all_balance(&mut self, account: &Self::Address) -> Result<Vec<Coin>, Self::Error> {
        self.charge(VmGas::AllBalance)?;
        self.0.as_context_mut().data_mut().all_balance(account)
    }

    #[cfg(feature = "cosmwasm_1_1")]
    fn supply(&mut self, denom: String) -> Result<Coin, Self::Error> {
        self.charge(VmGas::Supply)?;
        self.0.as_context_mut().data_mut().supply(denom)
    }

    fn query_contract_info(
        &mut self,
        address: Self::Address,
    ) -> Result<ContractInfoResponse, Self::Error> {
        self.charge(VmGas::QueryContractInfo)?;
        self.0
            .as_context_mut()
            .data_mut()
            .query_contract_info(address)
    }

    #[cfg(feature = "cosmwasm_1_2")]
    fn query_code_info(&mut self, id: CosmwasmCodeId) -> Result<CodeInfoResponse, Self::Error> {
        self.charge(VmGas::QueryCodeInfo)?;
        self.0.as_context_mut().data_mut().query_code_info(id)
    }

    fn debug(&mut self, message: Vec<u8>) -> Result<(), Self::Error> {
        self.charge(VmGas::Debug)?;
        self.0.as_context_mut().data_mut().debug(message)
    }

    fn db_read(
        &mut self,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error> {
        self.charge(VmGas::DbRead)?;
        self.0.as_context_mut().data_mut().db_read(key)
    }

    fn db_write(
        &mut self,
        key: Self::StorageKey,
        value: Self::StorageValue,
    ) -> Result<(), Self::Error> {
        self.charge(VmGas::DbWrite)?;
        self.0.as_context_mut().data_mut().db_write(key, value)
    }

    fn db_remove(&mut self, key: Self::StorageKey) -> Result<(), Self::Error> {
        self.charge(VmGas::DbRemove)?;
        self.0.as_context_mut().data_mut().db_remove(key)
    }

    fn addr_validate(&mut self, input: &str) -> Result<Result<(), Self::Error>, Self::Error> {
        self.charge(VmGas::AddrValidate)?;
        self.0.as_context_mut().data_mut().addr_validate(input)
    }

    fn addr_canonicalize(
        &mut self,
        input: &str,
    ) -> Result<Result<Self::CanonicalAddress, Self::Error>, Self::Error> {
        self.charge(VmGas::AddrCanonicalize)?;
        self.0.as_context_mut().data_mut().addr_canonicalize(input)
    }

    fn addr_humanize(
        &mut self,
        addr: &Self::CanonicalAddress,
    ) -> Result<Result<Self::Address, Self::Error>, Self::Error> {
        self.charge(VmGas::AddrHumanize)?;
        self.0.as_context_mut().data_mut().addr_humanize(addr)
    }

    fn abort(&mut self, message: String) -> Result<(), Self::Error> {
        self.0.as_context_mut().data_mut().abort(message)
    }

    fn charge(&mut self, value: VmGas) -> Result<(), Self::Error> {
        self.0.as_context_mut().data_mut().charge(value)
    }

    fn gas_checkpoint_push(&mut self, checkpoint: VmGasCheckpoint) -> Result<(), Self::Error> {
        self.0
            .as_context_mut()
            .data_mut()
            .gas_checkpoint_push(checkpoint)
    }

    fn gas_checkpoint_pop(&mut self) -> Result<(), Self::Error> {
        self.0.as_context_mut().data_mut().gas_checkpoint_pop()
    }

    fn gas_ensure_available(&mut self) -> Result<(), Self::Error> {
        self.0.as_context_mut().data_mut().gas_ensure_available()
    }

    fn secp256k1_verify(
        &mut self,
        message_hash: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Self::Error> {
        self.0
            .as_context_mut()
            .data_mut()
            .charge(VmGas::Secp256k1Verify)?;
        self.0
            .as_context_mut()
            .data_mut()
            .secp256k1_verify(message_hash, signature, public_key)
    }

    fn secp256k1_recover_pubkey(
        &mut self,
        message_hash: &[u8],
        signature: &[u8],
        recovery_param: u8,
    ) -> Result<Result<Vec<u8>, ()>, Self::Error> {
        self.charge(VmGas::Secp256k1RecoverPubkey)?;
        self.0.as_context_mut().data_mut().secp256k1_recover_pubkey(
            message_hash,
            signature,
            recovery_param,
        )
    }

    fn ed25519_verify(
        &mut self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Self::Error> {
        self.charge(VmGas::Ed25519Verify)?;
        self.0
            .as_context_mut()
            .data_mut()
            .ed25519_verify(message, signature, public_key)
    }

    fn ed25519_batch_verify(
        &mut self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<bool, Self::Error> {
        self.charge(VmGas::Ed25519BatchVerify)?;
        self.0
            .as_context_mut()
            .data_mut()
            .ed25519_batch_verify(messages, signatures, public_keys)
    }

    #[cfg(feature = "stargate")]
    fn ibc_transfer(
        &mut self,
        channel_id: String,
        to_address: String,
        amount: Coin,
        timeout: cosmwasm_std::IbcTimeout,
    ) -> Result<(), Self::Error> {
        self.charge(VmGas::IbcTransfer)?;
        self.0
            .as_context_mut()
            .data_mut()
            .ibc_transfer(channel_id, to_address, amount, timeout)
    }

    #[cfg(feature = "stargate")]
    fn ibc_send_packet(
        &mut self,
        channel_id: String,
        data: Binary,
        timeout: cosmwasm_std::IbcTimeout,
    ) -> Result<(), Self::Error> {
        self.charge(VmGas::IbcSendPacket)?;
        self.0
            .as_context_mut()
            .data_mut()
            .ibc_send_packet(channel_id, data, timeout)
    }

    #[cfg(feature = "stargate")]
    fn ibc_close_channel(&mut self, channel_id: String) -> Result<(), Self::Error> {
        self.charge(VmGas::IbcCloseChannel)?;
        self.0
            .as_context_mut()
            .data_mut()
            .ibc_close_channel(channel_id)
    }
}

impl<V, S> VM for WasmiVM<V, S>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    fn raw_call<'a, O>(
        &mut self,
        WasmiInput(
            WasmiFunctionName(function_name),
            WasmiFunctionParams(params),
            WasmiFunctionResult(mut result),
            _,
        ): Self::Input<'a>,
    ) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::Output<'x>, Error = VmErrorOf<Self>>,
    {
        log::trace!("Function name: {}", function_name);
        let WasmiModule { instance, .. } = self
            .0
            .as_context()
            .data()
            .executing_module()
            .ok_or(WasmiVMError::NotADynamicModule)?;

        // TODO(aeryz): Investigate typed calls, they avoid type checks so
        // could be beneficial for the performance. Also, it returns the
        // output instead of writing to a mutable reference.
        let export = instance
            .get_export(self.0.as_context(), &function_name)
            .and_then(Extern::into_func)
            .ok_or(WasmiVMError::FunctionNotFound)?;

        export.call(self.0.as_context_mut(), &params, &mut result)?;

        O::try_from(WasmiOutput(WasmiFunctionResult(result), PhantomData))
    }
}

impl<V, S> Pointable for WasmiVM<V, S>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Pointer = u32;
}

impl<V, S> ReadableMemory for WasmiVM<V, S>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Error = VmErrorOf<V>;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error> {
        let WasmiModule { memory, .. } = self
            .0
            .as_context()
            .data()
            .executing_module()
            .ok_or(WasmiVMError::NotADynamicModule)?;
        memory
            .read(self.0.as_context(), offset as usize, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryReadError.into())
    }
}

impl<V, S> WritableMemory for WasmiVM<V, S>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Error = VmErrorOf<V>;
    fn write(&mut self, offset: Self::Pointer, buffer: &[u8]) -> Result<(), Self::Error> {
        let WasmiModule { memory, .. } = self
            .0
            .as_context()
            .data()
            .executing_module()
            .ok_or(WasmiVMError::NotADynamicModule)?;
        memory
            .write(self.0.as_context_mut(), offset as usize, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryWriteError.into())
    }
}

impl<V, S> Transactional for WasmiVM<V, S>
where
    V: Transactional + WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Error = TransactionalErrorOf<V>;

    fn transaction_begin(&mut self) -> Result<(), Self::Error> {
        self.0.as_context_mut().data_mut().transaction_begin()
    }

    fn transaction_commit(&mut self) -> Result<(), Self::Error> {
        self.0.as_context_mut().data_mut().transaction_commit()
    }

    fn transaction_rollback(&mut self) -> Result<(), Self::Error> {
        self.0.as_context_mut().data_mut().transaction_rollback()
    }
}

impl<V: Has<U>, S, U> Has<U> for WasmiVM<V, S>
where
    V: Transactional + WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    fn get(&self) -> U {
        self.0.as_context().data().get()
    }
}
