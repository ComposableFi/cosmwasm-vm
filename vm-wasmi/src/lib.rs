// lib.rs ---

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

#![no_std]
#![feature(generic_associated_types)]
#![feature(trait_alias)]
#![cfg_attr(test, feature(assert_matches))]

extern crate alloc;

pub mod code_gen;
#[cfg(test)]
mod semantic;

use alloc::{borrow::ToOwned, collections::BTreeMap, format, string::String, vec, vec::Vec};
use core::{
    fmt::{Debug, Display},
    marker::PhantomData,
    num::TryFromIntError,
};
#[cfg(feature = "iterator")]
use cosmwasm_minimal_std::Order;
use cosmwasm_minimal_std::{
    Addr, Binary, CanonicalAddr, Coin, ContractInfoResponse, Env, Event, MessageInfo, SystemResult,
};
use cosmwasm_vm::executor::{
    AllocateInput, AsFunctionName, CosmwasmCallInput, CosmwasmCallWithoutInfoInput,
    CosmwasmQueryResult, DeallocateInput, ExecutorError, QueryResult, Unit,
};
use cosmwasm_vm::has::Has;
use cosmwasm_vm::memory::{
    MemoryReadError, MemoryWriteError, Pointable, PointerOf, ReadWriteMemory, ReadableMemory,
    ReadableMemoryErrorOf, WritableMemory, WritableMemoryErrorOf,
};
use cosmwasm_vm::system::{CosmwasmContractMeta, SystemError};
use cosmwasm_vm::tagged::Tagged;
use cosmwasm_vm::transaction::{Transactional, TransactionalErrorOf};
use cosmwasm_vm::vm::*;
use either::Either;
use wasmi::{CanResume, Externals, FuncInstance, ImportResolver, NopExternals, RuntimeValue};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WasmiFunctionName(String);
pub type WasmiFunctionArgs<'a> = (Vec<RuntimeValue>, PhantomData<&'a ()>);
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WasmiModuleName(String);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WasmiHostFunctionIndex(usize);
pub type WasmiHostFunction<T> =
    fn(&mut WasmiVM<T>, &[RuntimeValue]) -> Result<Option<RuntimeValue>, VmErrorOf<T>>;
pub type WasmiHostModuleEntry<T> = (WasmiHostFunctionIndex, WasmiHostFunction<T>);
pub type WasmiHostModule<T> = BTreeMap<WasmiFunctionName, WasmiHostModuleEntry<T>>;

#[derive(PartialEq, Eq, Debug)]
pub enum WasmiVMError {
    ExecutorError(ExecutorError),
    SystemError(SystemError),
    MemoryReadError(MemoryReadError),
    MemoryWriteError(MemoryWriteError),
    HostFunctionNotFound(WasmiHostFunctionIndex),
    MemoryNotExported,
    MemoryExportedIsNotMemory,
    LowLevelMemoryReadError,
    LowLevelMemoryWriteError,
    InvalidPointer,
    UnexpectedUnit,
    ExpectedUnit,
    InvalidHostSignature,
    InvalidValue,
    MaxLimitExceeded,
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
        write!(f, "{:?}", self)
    }
}

pub trait WasmiBaseVM = WasmiModuleExecutor
    + VMBase<
        ContractMeta = CosmwasmContractMeta<VmAddressOf<Self>>,
        StorageKey = Vec<u8>,
        StorageValue = Vec<u8>,
    > + ReadWriteMemory<Pointer = u32>
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
        + From<ReadableMemoryErrorOf<Self>>
        + From<WritableMemoryErrorOf<Self>>
        + From<ExecutorError>
        + From<SystemError>
        + From<TransactionalErrorOf<Self>>
        + Debug
        + Display
        + CanResume,
    ReadableMemoryErrorOf<Self>: From<MemoryReadError>,
    WritableMemoryErrorOf<Self>: From<MemoryWriteError>;

pub trait WasmiModuleExecutor: Sized + VMBase {
    fn executing_module(&self) -> WasmiModule;
    fn host_function(&self, index: WasmiHostFunctionIndex) -> Option<&WasmiHostFunction<Self>>;
}

pub struct WasmiVM<T>(pub T);
impl<T> Externals for WasmiVM<T>
where
    T: WasmiBaseVM,
{
    type Error = VmErrorOf<T>;
    fn invoke_index(
        &mut self,
        index: usize,
        args: wasmi::RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Self::Error> {
        self.0
            .host_function(WasmiHostFunctionIndex(index))
            .ok_or_else(|| {
                VmErrorOf::<T>::from(WasmiVMError::HostFunctionNotFound(WasmiHostFunctionIndex(
                    index,
                )))
            })?(self, args.as_ref())
    }
}

pub struct WasmiImportResolver<T: VMBase>(pub BTreeMap<WasmiModuleName, WasmiHostModule<T>>);
impl<T> ImportResolver for WasmiImportResolver<T>
where
    T: WasmiBaseVM,
{
    fn resolve_func(
        &self,
        module_name: &str,
        field_name: &str,
        signature: &wasmi::Signature,
    ) -> Result<wasmi::FuncRef, wasmi::Error> {
        let module = self
            .0
            .get(&WasmiModuleName(module_name.to_owned()))
            .ok_or_else(|| {
                wasmi::Error::Instantiation(format!(
                    "A module tried to load an unknown host module: {}",
                    module_name
                ))
            })?;
        let (WasmiHostFunctionIndex(function_index), _) = *module
            .get(&WasmiFunctionName(field_name.to_owned()))
            .ok_or_else(|| {
                wasmi::Error::Instantiation(format!(
                    "A module tried to load an unknown host function: {}.{}",
                    module_name, field_name
                ))
            })?;
        Ok(FuncInstance::alloc_host(signature.clone(), function_index))
    }

    fn resolve_global(
        &self,
        _: &str,
        _: &str,
        _: &wasmi::GlobalDescriptor,
    ) -> Result<wasmi::GlobalRef, wasmi::Error> {
        Err(wasmi::Error::Instantiation(
            "A CosmWasm contract is not allowed to import a global.".to_owned(),
        ))
    }

    fn resolve_memory(
        &self,
        _: &str,
        _: &str,
        _: &wasmi::MemoryDescriptor,
    ) -> Result<wasmi::MemoryRef, wasmi::Error> {
        Err(wasmi::Error::Instantiation(
            "A CosmWasm contract is not allowed to import a memory.".to_owned(),
        ))
    }

    fn resolve_table(
        &self,
        _: &str,
        _: &str,
        _: &wasmi::TableDescriptor,
    ) -> Result<wasmi::TableRef, wasmi::Error> {
        Err(wasmi::Error::Instantiation(
            "A CosmWasm contract is not allowed to import a table.".to_owned(),
        ))
    }
}

pub struct WasmiOutput<'a, T>(
    Either<&'a wasmi::MemoryRef, (&'a wasmi::MemoryRef, RuntimeValue)>,
    PhantomData<T>,
);

pub struct WasmiInput<'a, T>(WasmiFunctionName, WasmiFunctionArgs<'a>, PhantomData<T>);

#[derive(Clone)]
pub struct WasmiModule {
    pub module: wasmi::ModuleRef,
    pub memory: wasmi::MemoryRef,
}

impl<'a, T> TryFrom<WasmiOutput<'a, WasmiVM<T>>> for RuntimeValue
where
    T: WasmiBaseVM,
{
    type Error = VmErrorOf<T>;
    fn try_from(WasmiOutput(value, _): WasmiOutput<'a, WasmiVM<T>>) -> Result<Self, Self::Error> {
        match value {
            Either::Right((_, rt_value)) => Ok(rt_value),
            _ => Err(WasmiVMError::UnexpectedUnit.into()),
        }
    }
}

impl<'a, T> TryFrom<WasmiOutput<'a, WasmiVM<T>>> for Unit
where
    T: WasmiBaseVM,
{
    type Error = VmErrorOf<T>;
    fn try_from(WasmiOutput(value, _): WasmiOutput<'a, WasmiVM<T>>) -> Result<Self, Self::Error> {
        match value {
            Either::Left(_) => Ok(Unit),
            _ => Err(WasmiVMError::ExpectedUnit.into()),
        }
    }
}

impl<'a, T> TryFrom<WasmiOutput<'a, WasmiVM<T>>> for u32
where
    T: WasmiBaseVM,
{
    type Error = VmErrorOf<T>;
    fn try_from(WasmiOutput(value, _): WasmiOutput<'a, WasmiVM<T>>) -> Result<Self, Self::Error> {
        match value {
            Either::Right((_, RuntimeValue::I32(rt_value))) => Ok(rt_value as u32),
            _ => Err(WasmiVMError::UnexpectedUnit.into()),
        }
    }
}

impl<'a, T> TryFrom<AllocateInput<u32>> for WasmiInput<'a, WasmiVM<T>>
where
    T: WasmiBaseVM,
{
    type Error = VmErrorOf<T>;
    fn try_from(AllocateInput(ptr): AllocateInput<u32>) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName(AllocateInput::<u32>::NAME.into()),
            (vec![RuntimeValue::I32(ptr as i32)], PhantomData),
            PhantomData,
        ))
    }
}

impl<'a, T> TryFrom<DeallocateInput<u32>> for WasmiInput<'a, WasmiVM<T>>
where
    T: WasmiBaseVM,
{
    type Error = VmErrorOf<T>;
    fn try_from(DeallocateInput(ptr): DeallocateInput<u32>) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName(DeallocateInput::<u32>::NAME.into()),
            (vec![RuntimeValue::I32(ptr as i32)], PhantomData),
            PhantomData,
        ))
    }
}

impl<'a, I, T> TryFrom<CosmwasmCallInput<'a, u32, I>> for WasmiInput<'a, WasmiVM<T>>
where
    T: WasmiBaseVM,
    I: AsFunctionName,
{
    type Error = VmErrorOf<T>;
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

impl<'a, I, T> TryFrom<CosmwasmCallWithoutInfoInput<'a, u32, I>> for WasmiInput<'a, WasmiVM<T>>
where
    T: WasmiBaseVM,
    I: AsFunctionName,
{
    type Error = VmErrorOf<T>;
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

impl<T> VM for WasmiVM<T>
where
    T: WasmiBaseVM,
{
    fn raw_call<'a, O>(
        &mut self,
        WasmiInput(WasmiFunctionName(function_name), (function_args, _), _): Self::Input<'a>,
    ) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::Output<'x>, Error = VmErrorOf<Self>>,
    {
        log::trace!("Function name: {}", function_name);
        let WasmiModule { module, memory } = self.0.executing_module();
        let value = module.invoke_export(&function_name, &function_args, self)?;
        O::try_from(WasmiOutput(
            match value {
                Some(non_unit) => Either::Right((&memory, non_unit)),
                None => Either::Left(&memory),
            },
            PhantomData,
        ))
    }
}

impl<T> VMBase for WasmiVM<T>
where
    T: WasmiBaseVM,
{
    type Input<'x> = WasmiInput<'x, Self>;
    type Output<'x> = WasmiOutput<'x, Self>;
    type QueryCustom = VmQueryCustomOf<T>;
    type MessageCustom = VmMessageCustomOf<T>;
    type ContractMeta = VmContracMetaOf<T>;
    type Address = VmAddressOf<T>;
    type CanonicalAddress = VmCanonicalAddressOf<T>;
    type StorageKey = VmStorageKeyOf<T>;
    type StorageValue = VmStorageValueOf<T>;
    type Error = VmErrorOf<T>;

    fn running_contract_meta(&mut self) -> Result<Self::ContractMeta, Self::Error> {
        self.charge(VmGas::GetContractMeta)?;
        self.0.running_contract_meta()
    }

    #[cfg(feature = "iterator")]
    fn db_scan(
        &mut self,
        start: Option<Self::StorageKey>,
        end: Option<Self::StorageKey>,
        order: Order,
    ) -> Result<u32, Self::Error> {
        self.charge(VmGas::DbScan)?;
        self.0.db_scan(start, end, order)
    }

    #[cfg(feature = "iterator")]
    fn db_next(
        &mut self,
        iterator_id: u32,
    ) -> Result<(Self::StorageKey, Self::StorageValue), Self::Error> {
        self.charge(VmGas::DbNext)?;
        self.0.db_next(iterator_id)
    }

    fn set_contract_meta(
        &mut self,
        address: Self::Address,
        new_contract_meta: Self::ContractMeta,
    ) -> Result<(), Self::Error> {
        self.charge(VmGas::SetContractMeta)?;
        self.0.set_contract_meta(address, new_contract_meta)
    }

    fn contract_meta(&mut self, address: Self::Address) -> Result<Self::ContractMeta, Self::Error> {
        self.charge(VmGas::GetContractMeta)?;
        self.0.contract_meta(address)
    }

    fn query_continuation(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<QueryResult, Self::Error> {
        self.charge(VmGas::QueryContinuation)?;
        self.0.query_continuation(address, message)
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
        self.0
            .continue_instantiate(contract_meta, funds, message, event_handler)
    }

    fn continue_migrate(
        &mut self,
        address: Self::Address,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.charge(VmGas::ContinueMigrate)?;
        self.0.continue_migrate(address, message, event_handler)
    }

    fn query_custom(
        &mut self,
        query: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, Self::Error> {
        self.charge(VmGas::QueryCustom)?;
        self.0.query_custom(query)
    }

    fn message_custom(
        &mut self,
        message: Self::MessageCustom,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.charge(VmGas::MessageCustom)?;
        self.0.message_custom(message, event_handler)
    }

    fn query_raw(
        &mut self,
        address: Self::Address,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error> {
        self.charge(VmGas::QueryRaw)?;
        self.0.query_raw(address, key)
    }

    fn transfer(&mut self, to: &Self::Address, funds: &[Coin]) -> Result<(), Self::Error> {
        self.charge(VmGas::Transfer {
            nb_of_coins: u32::try_from(funds.len()).map_err(|_| WasmiVMError::MaxLimitExceeded)?,
        })?;
        self.0.transfer(to, funds)
    }

    fn burn(&mut self, funds: &[Coin]) -> Result<(), Self::Error> {
        self.charge(VmGas::Burn)?;
        self.0.burn(funds)
    }

    fn balance(&mut self, account: &Self::Address, denom: String) -> Result<Coin, Self::Error> {
        self.charge(VmGas::Balance)?;
        self.0.balance(account, denom)
    }

    fn all_balance(&mut self, account: &Self::Address) -> Result<Vec<Coin>, Self::Error> {
        self.charge(VmGas::AllBalance)?;
        self.0.all_balance(account)
    }

    fn query_info(&mut self, address: Self::Address) -> Result<ContractInfoResponse, Self::Error> {
        self.charge(VmGas::QueryInfo)?;
        self.0.query_info(address)
    }

    fn debug(&mut self, message: Vec<u8>) -> Result<(), Self::Error> {
        self.charge(VmGas::Debug)?;
        self.0.debug(message)
    }

    fn db_read(
        &mut self,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error> {
        self.charge(VmGas::DbRead)?;
        self.0.db_read(key)
    }

    fn db_write(
        &mut self,
        key: Self::StorageKey,
        value: Self::StorageValue,
    ) -> Result<(), Self::Error> {
        self.0.charge(VmGas::DbWrite)?;
        self.0.db_write(key, value)
    }

    fn db_remove(&mut self, key: Self::StorageKey) -> Result<(), Self::Error> {
        self.0.charge(VmGas::DbRemove)?;
        self.0.db_remove(key)
    }

    fn addr_validate(&mut self, input: &str) -> Result<Result<(), Self::Error>, Self::Error> {
        self.0.charge(VmGas::AddrValidate)?;
        self.0.addr_validate(input)
    }

    fn addr_canonicalize(
        &mut self,
        input: &str,
    ) -> Result<Result<Self::CanonicalAddress, Self::Error>, Self::Error> {
        self.0.charge(VmGas::AddrCanonicalize)?;
        self.0.addr_canonicalize(input)
    }

    fn addr_humanize(
        &mut self,
        addr: &Self::CanonicalAddress,
    ) -> Result<Result<Self::Address, Self::Error>, Self::Error> {
        self.0.charge(VmGas::AddrHumanize)?;
        self.0.addr_humanize(addr)
    }

    fn abort(&mut self, message: String) -> Result<(), Self::Error> {
        self.0.abort(message)
    }

    fn charge(&mut self, value: VmGas) -> Result<(), Self::Error> {
        self.0.charge(value)
    }

    fn gas_checkpoint_push(&mut self, checkpoint: VmGasCheckpoint) -> Result<(), Self::Error> {
        self.0.gas_checkpoint_push(checkpoint)
    }

    fn gas_checkpoint_pop(&mut self) -> Result<(), Self::Error> {
        self.0.gas_checkpoint_pop()
    }

    fn gas_ensure_available(&mut self) -> Result<(), Self::Error> {
        self.0.gas_ensure_available()
    }

    fn secp256k1_verify(
        &mut self,
        message_hash: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Self::Error> {
        self.0.charge(VmGas::Secp256k1Verify)?;
        self.0.secp256k1_verify(message_hash, signature, public_key)
    }

    fn secp256k1_recover_pubkey(
        &mut self,
        message_hash: &[u8],
        signature: &[u8],
        recovery_param: u8,
    ) -> Result<Result<Vec<u8>, ()>, Self::Error> {
        self.0.charge(VmGas::Secp256k1RecoverPubkey)?;
        self.0
            .secp256k1_recover_pubkey(message_hash, signature, recovery_param)
    }

    fn ed25519_verify(
        &mut self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Self::Error> {
        self.0.charge(VmGas::Ed25519Verify)?;
        self.0.ed25519_verify(message, signature, public_key)
    }

    fn ed25519_batch_verify(
        &mut self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<bool, Self::Error> {
        self.0.charge(VmGas::Ed25519BatchVerify)?;
        self.0
            .ed25519_batch_verify(messages, signatures, public_keys)
    }

    #[cfg(feature = "stargate")]
    fn ibc_transfer(
        &mut self,
        channel_id: String,
        to_address: String,
        amount: Coin,
        timeout: cosmwasm_minimal_std::ibc::IbcTimeout,
    ) -> Result<(), Self::Error> {
        self.0.charge(VmGas::IbcTransfer)?;
        self.0.ibc_transfer(channel_id, to_address, amount, timeout)
    }

    #[cfg(feature = "stargate")]
    fn ibc_send_packet(
        &mut self,
        channel_id: String,
        data: Binary,
        timeout: cosmwasm_minimal_std::ibc::IbcTimeout,
    ) -> Result<(), Self::Error> {
        self.0.charge(VmGas::IbcSendPacket)?;
        self.0.ibc_send_packet(channel_id, data, timeout)
    }

    #[cfg(feature = "stargate")]
    fn ibc_close_channel(&mut self, channel_id: String) -> Result<(), Self::Error> {
        self.0.charge(VmGas::IbcCloseChannel)?;
        self.0.ibc_close_channel(channel_id)
    }
}

impl<T> Transactional for WasmiVM<T>
where
    T: Transactional,
{
    type Error = TransactionalErrorOf<T>;
    fn transaction_begin(&mut self) -> Result<(), Self::Error> {
        self.0.transaction_begin()
    }
    fn transaction_commit(&mut self) -> Result<(), Self::Error> {
        self.0.transaction_commit()
    }
    fn transaction_rollback(&mut self) -> Result<(), Self::Error> {
        self.0.transaction_rollback()
    }
}

impl<T: Has<U>, U> Has<U> for WasmiVM<T> {
    fn get(&self) -> U {
        self.0.get()
    }
}

pub fn new_wasmi_vm<T>(
    resolver: &WasmiImportResolver<T>,
    code: &[u8],
) -> Result<WasmiModule, VmErrorOf<T>>
where
    T: WasmiBaseVM,
{
    let wasmi_module = wasmi::Module::from_buffer(code)?;
    let not_started_module_instance = wasmi::ModuleInstance::new(&wasmi_module, resolver)?;
    let module_instance =
        not_started_module_instance.run_start(&mut NopExternals(PhantomData::<VmErrorOf<T>>))?;
    let memory_exported = module_instance
        .export_by_name("memory")
        .ok_or(WasmiVMError::MemoryNotExported)?;
    let memory = match memory_exported {
        wasmi::ExternVal::Memory(mem) => Ok(mem),
        _ => Err(WasmiVMError::MemoryExportedIsNotMemory),
    }?;
    Ok(WasmiModule {
        module: module_instance,
        memory,
    })
}

impl<T> Pointable for WasmiVM<T>
where
    T: WasmiBaseVM,
{
    type Pointer = PointerOf<T>;
}

impl<T> ReadableMemory for WasmiVM<T>
where
    T: WasmiBaseVM,
{
    type Error = ReadableMemoryErrorOf<T>;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read(offset, buffer)
    }
}

impl<T> WritableMemory for WasmiVM<T>
where
    T: WasmiBaseVM,
{
    type Error = WritableMemoryErrorOf<T>;
    fn write(&self, offset: Self::Pointer, buffer: &[u8]) -> Result<(), Self::Error> {
        self.0.write(offset, buffer)
    }
}

impl<T> ReadWriteMemory for WasmiVM<T> where T: WasmiBaseVM {}

#[cfg(feature = "iterator")]
/// Encodes multiple sections of data into one vector.
///
/// Each section is suffixed by a section length encoded as big endian uint32.
/// Using suffixes instead of prefixes allows reading sections in reverse order,
/// such that the first element does not need to be re-allocated if the contract's
/// data structure supports truncation (such as a Rust vector).
///
/// The resulting data looks like this:
///
/// ```ignore
/// section1 || section1_len || section2 || section2_len || section3 || section3_len || …
/// ```
pub fn encode_sections(sections: &[Vec<u8>]) -> Option<Vec<u8>> {
    let out_len: usize =
        sections.iter().map(|section| section.len()).sum::<usize>() + 4 * sections.len();
    sections
        .iter()
        .fold(Some(Vec::with_capacity(out_len)), |acc, section| {
            acc.and_then(|mut acc| {
                TryInto::<u32>::try_into(section.len())
                    .map(|section_len| {
                        acc.extend(section);
                        acc.extend_from_slice(&section_len.to_be_bytes());
                        acc
                    })
                    .ok()
            })
        })
}

/// Decodes sections of data into multiple slices.
///
/// Each encoded section is suffixed by a section length, encoded as big endian uint32.
///
/// See also: `encode_section`.
pub fn decode_sections(data: &[u8]) -> Vec<&[u8]> {
    let mut result: Vec<&[u8]> = vec![];
    let mut remaining_len = data.len();
    while remaining_len >= 4 {
        let tail_len = u32::from_be_bytes([
            data[remaining_len - 4],
            data[remaining_len - 3],
            data[remaining_len - 2],
            data[remaining_len - 1],
        ]) as usize;
        result.push(&data[remaining_len - 4 - tail_len..remaining_len - 4]);
        remaining_len -= 4 + tail_len;
    }
    result.reverse();
    result
}

#[allow(dead_code)]
pub mod host_functions {
    use super::*;
    #[cfg(feature = "iterator")]
    use cosmwasm_minimal_std::Order;
    use cosmwasm_minimal_std::QueryRequest;
    use cosmwasm_vm::{
        executor::{
            constants, marshall_out, passthrough_in, passthrough_in_to, passthrough_out,
            ConstantReadLimit,
        },
        system::cosmwasm_system_query_raw,
    };

    pub fn definitions<T>() -> BTreeMap<WasmiModuleName, WasmiHostModule<T>>
    where
        T: WasmiBaseVM,
    {
        BTreeMap::from([(
            WasmiModuleName("env".to_owned()),
            BTreeMap::from([
                (
                    WasmiFunctionName("db_read".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0001),
                        env_db_read::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("db_write".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0002),
                        env_db_write::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("db_remove".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0003),
                        env_db_remove::<T> as WasmiHostFunction<T>,
                    ),
                ),
                #[cfg(feature = "iterator")]
                (
                    WasmiFunctionName("db_scan".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0004),
                        env_db_scan::<T> as WasmiHostFunction<T>,
                    ),
                ),
                #[cfg(feature = "iterator")]
                (
                    WasmiFunctionName("db_next".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0005),
                        env_db_next::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_validate".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0006),
                        env_addr_validate::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_canonicalize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0007),
                        env_addr_canonicalize::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_humanize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0008),
                        env_addr_humanize::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0009),
                        env_secp256k1_verify::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_recover_pubkey".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000B),
                        env_secp256k1_recover_pubkey::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000C),
                        env_ed25519_verify::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000D),
                        env_ed25519_batch_verify::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("debug".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000E),
                        env_debug::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("query_chain".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000F),
                        env_query_chain::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("abort".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0010),
                        env_abort::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("gas".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0011),
                        env_gas::<T> as WasmiHostFunction<T>,
                    ),
                ),
            ]),
        )])
    }

    fn env_db_read<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("db_read");
        match values {
            [RuntimeValue::I32(key_pointer)] => {
                let key = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>,
                >(vm, *key_pointer as u32)?;
                let value = vm.db_read(key);
                match value {
                    Ok(Some(value)) => {
                        let Tagged(value_pointer, _) =
                            passthrough_in::<WasmiVM<T>, ()>(vm, &value)?;
                        Ok(Some(RuntimeValue::I32(value_pointer as i32)))
                    }
                    Ok(None) => Ok(Some(RuntimeValue::I32(0))),
                    Err(e) => Err(e),
                }
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_db_write<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("db_write");
        match values {
            [RuntimeValue::I32(key_pointer), RuntimeValue::I32(value_pointer)] => {
                let key = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>,
                >(vm, *key_pointer as u32)?;
                let value = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_DB_VALUE }>,
                >(vm, *value_pointer as u32)?;
                vm.db_write(key, value)?;
                Ok(None)
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_db_remove<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("db_remove");
        match values {
            [RuntimeValue::I32(key_pointer)] => {
                let key = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>,
                >(vm, *key_pointer as u32)?;
                vm.db_remove(key)?;
                Ok(None)
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    #[cfg(feature = "iterator")]
    fn env_db_scan<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("db_scan");
        match values {
            [RuntimeValue::I32(start_ptr), RuntimeValue::I32(end_ptr), RuntimeValue::I32(order)] => {
                let start = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>,
                >(vm, *start_ptr as u32)?;
                let end = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>,
                >(vm, *end_ptr as u32)?;
                let order: Order =
                    TryInto::<Order>::try_into(*order).map_err(|_| WasmiVMError::InvalidValue)?;
                let value = vm.db_scan(
                    if start.is_empty() { None } else { Some(start) },
                    if end.is_empty() { None } else { Some(end) },
                    order,
                )?;
                Ok(Some(RuntimeValue::I32(value as i32)))
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    #[cfg(feature = "iterator")]
    fn env_db_next<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("db_next");
        match values {
            [RuntimeValue::I32(iterator_id)] => {
                let next = vm.db_next(*iterator_id as u32);
                match next {
                    Ok((key, value)) => {
                        let out_data =
                            encode_sections(&[key, value]).ok_or(WasmiVMError::InvalidValue)?;
                        let Tagged(value_pointer, _) =
                            passthrough_in::<WasmiVM<T>, ()>(vm, &out_data)?;
                        Ok(Some(RuntimeValue::I32(value_pointer as i32)))
                    }
                    Err(e) => Err(e),
                }
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_addr_validate<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("addr_validate");
        match values {
            [RuntimeValue::I32(address_pointer)] => {
                let address = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_HUMAN_ADDRESS }>,
                >(vm, *address_pointer as u32)?;

                let address = match String::from_utf8(address) {
                    Ok(address) => address,
                    Err(e) => {
                        let Tagged(value_pointer, _) =
                            passthrough_in::<WasmiVM<T>, ()>(vm, e.as_bytes())?;
                        return Ok(Some(RuntimeValue::I32(value_pointer as i32)));
                    }
                };

                match vm.addr_validate(&address)? {
                    Ok(_) => Ok(Some(RuntimeValue::I32(0))),
                    Err(e) => {
                        let Tagged(value_pointer, _) =
                            passthrough_in::<WasmiVM<T>, ()>(vm, format!("{}", e).as_bytes())?;
                        Ok(Some(RuntimeValue::I32(value_pointer as i32)))
                    }
                }
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_addr_canonicalize<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("addr_canonicalize");
        match values {
            [RuntimeValue::I32(address_pointer), RuntimeValue::I32(destination_pointer)] => {
                let address = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_HUMAN_ADDRESS }>,
                >(vm, *address_pointer as u32)?;

                let address = match String::from_utf8(address) {
                    Ok(address) => address,
                    Err(e) => {
                        let Tagged(value_pointer, _) =
                            passthrough_in::<WasmiVM<T>, ()>(vm, format!("{}", e).as_bytes())?;
                        return Ok(Some(RuntimeValue::I32(value_pointer as i32)));
                    }
                };

                match vm.addr_canonicalize(&address)? {
                    Ok(canonical_address) => {
                        passthrough_in_to::<WasmiVM<T>>(
                            vm,
                            *destination_pointer as u32,
                            &canonical_address.into(),
                        )?;
                        Ok(Some(RuntimeValue::I32(0)))
                    }
                    Err(e) => {
                        let Tagged(value_pointer, _) =
                            passthrough_in::<WasmiVM<T>, ()>(vm, format!("{}", e).as_bytes())?;
                        Ok(Some(RuntimeValue::I32(value_pointer as i32)))
                    }
                }
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_addr_humanize<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("addr_humanize");
        match values {
            [RuntimeValue::I32(address_pointer), RuntimeValue::I32(destination_pointer)] => {
                let address = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_CANONICAL_ADDRESS }>,
                >(vm, *address_pointer as u32)?;

                match vm.addr_humanize(&address.try_into()?)? {
                    Ok(address) => {
                        passthrough_in_to::<WasmiVM<T>>(
                            vm,
                            *destination_pointer as u32,
                            address.into().as_bytes(),
                        )?;
                        Ok(Some(RuntimeValue::I32(0)))
                    }
                    Err(e) => {
                        let Tagged(value_pointer, _) =
                            passthrough_in::<WasmiVM<T>, ()>(vm, format!("{}", e).as_bytes())?;
                        Ok(Some(RuntimeValue::I32(value_pointer as i32)))
                    }
                }
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_secp256k1_verify<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        match values {
            [RuntimeValue::I32(message_hash_ptr), RuntimeValue::I32(signature_ptr), RuntimeValue::I32(public_key_ptr)] =>
            {
                let message_hash = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_MESSAGE_HASH }>,
                >(vm, *message_hash_ptr as u32)?;
                let signature = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::EDCSA_SIGNATURE_LENGTH }>,
                >(vm, *signature_ptr as u32)?;
                let public_key = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_EDCSA_PUBKEY_LENGTH }>,
                >(vm, *public_key_ptr as u32)?;

                let result = vm.secp256k1_verify(&message_hash, &signature, &public_key)?;

                Ok(Some(RuntimeValue::I32(!result as i32)))
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_secp256k1_recover_pubkey<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("secp256k1_recover_pubkey");
        match values {
            [RuntimeValue::I32(message_hash_ptr), RuntimeValue::I32(signature_ptr), RuntimeValue::I32(recovery_param)] =>
            {
                let message_hash = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_MESSAGE_HASH }>,
                >(vm, *message_hash_ptr as u32)?;
                let signature = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::EDCSA_SIGNATURE_LENGTH }>,
                >(vm, *signature_ptr as u32)?;

                match vm.secp256k1_recover_pubkey(
                    &message_hash,
                    &signature,
                    *recovery_param as u8,
                )? {
                    // Note that if the call is success, the pointer is written to the lower
                    // 4-bytes. On failure, the error code is written to the upper 4-bytes, and
                    // we don't return an error.
                    Ok(pubkey) => {
                        let Tagged(value_pointer, _) =
                            passthrough_in::<WasmiVM<T>, ()>(vm, &pubkey)?;
                        Ok(Some(RuntimeValue::I64(value_pointer as i64)))
                    }
                    Err(_) => {
                        const GENERIC_ERROR_CODE: i64 = 10;
                        Ok(Some(RuntimeValue::I64(1_i64 << 32)))
                    }
                }
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_ed25519_verify<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("ed25519_verify");
        match values {
            [RuntimeValue::I32(message_ptr), RuntimeValue::I32(signature_ptr), RuntimeValue::I32(public_key_ptr)] =>
            {
                let message = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_ED25519_MESSAGE }>,
                >(vm, *message_ptr as u32)?;
                let signature = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_ED25519_SIGNATURE }>,
                >(vm, *signature_ptr as u32)?;
                let public_key = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::EDDSA_PUBKEY_LENGTH }>,
                >(vm, *public_key_ptr as u32)?;

                vm.ed25519_verify(&message, &signature, &public_key)
                    .map(|result| Some(RuntimeValue::I32(!result as i32)))
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_ed25519_batch_verify<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        match values {
            [RuntimeValue::I32(messages_pointer), RuntimeValue::I32(signatures_pointer), RuntimeValue::I32(public_keys_pointer)] =>
            {
                // &[&[u8]]'s are written to the memory in an flattened encoded way. That's why we
                // read a flat memory, not iterate through pointers and read arbitrary memory
                // locations.
                let messages = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<
                        {
                            (constants::MAX_LENGTH_ED25519_MESSAGE + 4)
                                * constants::MAX_COUNT_ED25519_BATCH
                        },
                    >,
                >(vm, *messages_pointer as u32)?;
                let signatures = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<
                        {
                            (constants::MAX_LENGTH_ED25519_SIGNATURE + 4)
                                * constants::MAX_COUNT_ED25519_BATCH
                        },
                    >,
                >(vm, *signatures_pointer as u32)?;
                let public_keys = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<
                        {
                            (constants::EDDSA_PUBKEY_LENGTH + 4)
                                * constants::MAX_COUNT_ED25519_BATCH
                        },
                    >,
                >(vm, *public_keys_pointer as u32)?;

                let (messages, signatures, public_keys) = (
                    decode_sections(&messages),
                    decode_sections(&signatures),
                    decode_sections(&public_keys),
                );

                vm.ed25519_batch_verify(&messages, &signatures, &public_keys)
                    .map(|result| Some(RuntimeValue::I32(!result as i32)))
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_debug<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("debug");
        match values {
            [RuntimeValue::I32(message_pointer)] => {
                let message: Vec<u8> = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_ABORT }>,
                >(vm, *message_pointer as u32)?;
                vm.debug(message)?;
                Ok(None)
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_query_chain<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("query_chain");
        match values {
            [RuntimeValue::I32(query_pointer)] => {
                let request = marshall_out::<WasmiVM<T>, QueryRequest<VmQueryCustomOf<T>>>(
                    vm,
                    *query_pointer as u32,
                )?;
                let value = cosmwasm_system_query_raw::<WasmiVM<T>>(vm, request)?;
                let Tagged(value_pointer, _) = passthrough_in::<WasmiVM<T>, ()>(vm, &value)?;
                Ok(Some(RuntimeValue::I32(value_pointer as i32)))
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_abort<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("abort");
        match values {
            [RuntimeValue::I32(message_pointer)] => {
                let message: Vec<u8> = passthrough_out::<
                    WasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_ABORT }>,
                >(vm, *message_pointer as u32)?;
                vm.abort(String::from_utf8_lossy(&message).into())?;
                Ok(None)
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_gas<T>(
        vm: &mut WasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        match values {
            [RuntimeValue::I32(value)] => {
                vm.charge(VmGas::Instrumentation {
                    metered: *value as u32,
                })?;
                Ok(None)
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }
}
