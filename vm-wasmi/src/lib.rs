#![no_std]
#![feature(trait_alias)]
#![cfg_attr(test, feature(assert_matches))]

extern crate alloc;

pub mod code_gen;
pub mod validation;
pub mod version;

#[cfg(test)]
mod semantic;

use alloc::{format, string::String, vec, vec::Vec};
use core::{
    fmt::{Debug, Display},
    marker::PhantomData,
    num::TryFromIntError,
};
#[cfg(feature = "iterator")]
use cosmwasm_std::Order;
use cosmwasm_std::{
    Addr, Binary, CanonicalAddr, Coin, ContractInfoResponse, Env, Event, MessageInfo, Reply,
    SystemResult,
};
use cosmwasm_vm::{
    executor::{
        AllocateCall, AsFunctionName, CosmwasmCallInput, CosmwasmCallWithoutInfoInput,
        CosmwasmQueryResult, DeallocateCall, ExecutorError, QueryResult, Unit,
    },
    has::Has,
    memory::{
        MemoryReadError, MemoryWriteError, Pointable, ReadWriteMemory, ReadableMemory,
        WritableMemory,
    },
    system::{CosmwasmContractMeta, SystemError},
    tagged::Tagged,
    transaction::{Transactional, TransactionalErrorOf},
    vm::{
        VMBase, VmAddressOf, VmCanonicalAddressOf, VmContracMetaOf, VmErrorOf, VmGas,
        VmGasCheckpoint, VmMessageCustomOf, VmQueryCustomOf, VmStorageKeyOf, VmStorageValueOf, VM,
    },
};
use wasmi::{
    core::Value as RuntimeValue, AsContextMut, Engine, Extern, Instance, Linker, Memory, Module,
    Store,
};

mod host_functions;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WasmiFunctionName(String);

pub type WasmiFunctionArgs<'a> = (Vec<RuntimeValue>, PhantomData<&'a ()>);

#[derive(PartialEq, Eq, Debug)]
pub enum WasmiVMError {
    ExecutorError(ExecutorError),
    SystemError(SystemError),
    MemoryReadError(MemoryReadError),
    MemoryWriteError(MemoryWriteError),
    MemoryNotExported,
    MemoryExportedIsNotMemory,
    LowLevelMemoryReadError,
    LowLevelMemoryWriteError,
    InvalidPointer,
    UnexpectedUnit,
    ExpectedUnit,
    ExpectedPointer,
    InvalidHostSignature,
    InvalidValue,
    MaxLimitExceeded,
    NotADynamicModule,
    FunctionNotFound,
    InternalWasmiError,
}
impl From<ExecutorError> for WasmiVMError {
    fn from(e: ExecutorError) -> Self {
        WasmiVMError::ExecutorError(e)
    }
}
impl From<MemoryReadError> for WasmiVMError {
    fn from(e: MemoryReadError) -> Self {
        WasmiVMError::MemoryReadError(e)
    }
}
impl From<MemoryWriteError> for WasmiVMError {
    fn from(e: MemoryWriteError) -> Self {
        WasmiVMError::MemoryWriteError(e)
    }
}
impl From<SystemError> for WasmiVMError {
    fn from(e: SystemError) -> Self {
        WasmiVMError::SystemError(e)
    }
}
impl From<TryFromIntError> for WasmiVMError {
    fn from(_: TryFromIntError) -> Self {
        WasmiVMError::InvalidPointer
    }
}
impl Display for WasmiVMError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub struct WasmiOutput<T>(Option<RuntimeValue>, PhantomData<T>);

pub struct WasmiInput<'a, T>(WasmiFunctionName, WasmiFunctionArgs<'a>, PhantomData<T>);

impl<V, S> TryFrom<WasmiOutput<WasmiVM<V, S>>> for RuntimeValue
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Error = VmErrorOf<V>;
    fn try_from(WasmiOutput(value, _): WasmiOutput<WasmiVM<V, S>>) -> Result<Self, Self::Error> {
        value.ok_or(WasmiVMError::UnexpectedUnit.into())
    }
}

impl<V, S> TryFrom<WasmiOutput<WasmiVM<V, S>>> for Unit
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Error = VmErrorOf<V>;
    fn try_from(WasmiOutput(value, _): WasmiOutput<WasmiVM<V, S>>) -> Result<Self, Self::Error> {
        if value.is_none() {
            Ok(Unit)
        } else {
            Err(WasmiVMError::ExpectedUnit.into())
        }
    }
}

impl<V, S> TryFrom<WasmiOutput<WasmiVM<V, S>>> for u32
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Error = VmErrorOf<V>;
    fn try_from(WasmiOutput(value, _): WasmiOutput<WasmiVM<V, S>>) -> Result<Self, Self::Error> {
        // we target wasm32 so this will not truncate
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            clippy::cast_sign_loss
        )]
        match value {
            Some(RuntimeValue::I32(rt_value)) => Ok(rt_value as u32),
            _ => Err(WasmiVMError::ExpectedPointer.into()),
        }
    }
}

impl<'a, V, S> TryFrom<AllocateCall<u32>> for WasmiInput<'a, WasmiVM<V, S>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Error = VmErrorOf<V>;
    // we target wasm32 so this will not truncate
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn try_from(AllocateCall(ptr): AllocateCall<u32>) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName(AllocateCall::<u32>::NAME.into()),
            (vec![RuntimeValue::I32(ptr as i32)], PhantomData),
            PhantomData,
        ))
    }
}

impl<'a, V, S> TryFrom<DeallocateCall<u32>> for WasmiInput<'a, WasmiVM<V, S>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Error = VmErrorOf<V>;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn try_from(DeallocateCall(ptr): DeallocateCall<u32>) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName(DeallocateCall::<u32>::NAME.into()),
            (vec![RuntimeValue::I32(ptr as i32)], PhantomData),
            PhantomData,
        ))
    }
}

impl<'a, I, V, S> TryFrom<CosmwasmCallInput<'a, u32, I>> for WasmiInput<'a, WasmiVM<V, S>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
    I: AsFunctionName,
{
    type Error = VmErrorOf<V>;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    fn try_from(
        CosmwasmCallInput(Tagged(env_ptr, _), Tagged(info_ptr, _), Tagged(msg_ptr, _), _): CosmwasmCallInput<'a, u32, I>,
    ) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName(I::NAME.into()),
            (
                vec![
                    RuntimeValue::I32(env_ptr as i32),
                    RuntimeValue::I32(info_ptr as i32),
                    RuntimeValue::I32(msg_ptr as i32),
                ],
                PhantomData,
            ),
            PhantomData,
        ))
    }
}

impl<'a, I, V, S> TryFrom<CosmwasmCallWithoutInfoInput<'a, u32, I>>
    for WasmiInput<'a, WasmiVM<V, S>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
    I: AsFunctionName,
{
    type Error = VmErrorOf<V>;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    fn try_from(
        CosmwasmCallWithoutInfoInput(Tagged(env_ptr, _), Tagged(msg_ptr, _), _): CosmwasmCallWithoutInfoInput<
            'a,
            u32,
            I,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName(I::NAME.into()),
            (
                vec![
                    RuntimeValue::I32(env_ptr as i32),
                    RuntimeValue::I32(msg_ptr as i32),
                ],
                PhantomData,
            ),
            PhantomData,
        ))
    }
}

impl<V, S> VM for WasmiVM<V, S>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    fn raw_call<'a, O>(
        &mut self,
        WasmiInput(WasmiFunctionName(function_name), (function_args, _), _): Self::Input<'a>,
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
        let export = instance
            .get_export(self.0.as_context(), &function_name)
            .and_then(Extern::into_func)
            .ok_or(WasmiVMError::FunctionNotFound)?;

        // Since all of the output types are either returning a single value or nothing,
        // we don't pay for storing and copying a "Vec" here
        let output = if export.func_type(self.0.as_context()).results().is_empty() {
            export
                .call(self.0.as_context_mut(), &function_args, &mut [])
                .map_err(|_| WasmiVMError::InternalWasmiError)?;
            WasmiOutput(None, PhantomData)
        } else {
            let mut value = [RuntimeValue::I32(0)];
            export
                .call(self.0.as_context_mut(), &function_args, &mut value)
                .map_err(|_| WasmiVMError::InternalWasmiError)?;
            WasmiOutput(Some(value[0]), PhantomData)
        };

        O::try_from(output)
    }
}

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

#[derive(Clone)]
pub struct WasmiModule {
    pub instance: Instance,
    pub memory: Memory,
}

pub trait WasmiContext {
    fn executing_module(&self) -> Option<WasmiModule>;

    fn set_wasmi_context(&mut self, instance: Instance, memory: Memory);
}

pub struct WasmiVM<V: WasmiBaseVM, S: AsContextMut<UserState = V>>(pub S);

impl<V, S> VMBase for WasmiVM<V, S>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    type Input<'x> = WasmiInput<'x, Self>;
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

    fn query_info(&mut self, address: Self::Address) -> Result<ContractInfoResponse, Self::Error> {
        self.charge(VmGas::QueryInfo)?;
        self.0.as_context_mut().data_mut().query_info(address)
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

/// Note that validation is not done here since the implementors probably wouldn't want
/// to do an expensive validation on each time they load the same code. So DO NOT forget
/// to use `CodeValidation` to properly validate the wasm module.
pub fn new_wasmi_vm<V: WasmiBaseVM, S: AsContextMut<UserState = V>>(
    code: &[u8],
    data: V,
) -> Result<WasmiVM<V, Store<V>>, VmErrorOf<V>> {
    let engine = Engine::default();
    let module = Module::new(&engine, code).map_err(|_| WasmiVMError::InternalWasmiError)?;

    let mut store = Store::new(&engine, data);
    let mut linker = <Linker<V>>::new();

    host_functions::define(store.as_context_mut(), &mut linker)?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|_| WasmiVMError::InternalWasmiError)?
        .start(&mut store)
        .map_err(|_| WasmiVMError::InternalWasmiError)?;

    let memory = instance
        .get_export(store.as_context_mut(), "memory")
        .and_then(Extern::into_memory)
        .ok_or(WasmiVMError::MemoryNotExported)?;

    store.data_mut().set_wasmi_context(instance, memory);

    Ok(WasmiVM(store))
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

impl<V, S> ReadWriteMemory for WasmiVM<V, S>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
}
