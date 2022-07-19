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

#[cfg(test)]
#[macro_use]
extern crate std;

extern crate alloc;

#[cfg(test)]
mod semantic;

use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::fmt::Display;
use core::marker::PhantomData;
use core::num::TryFromIntError;
use cosmwasm_minimal_std::Addr;
use cosmwasm_minimal_std::Binary;
use cosmwasm_minimal_std::Coin;
use cosmwasm_minimal_std::ContractInfoResponse;
use cosmwasm_minimal_std::CosmwasmQueryResult;
use cosmwasm_minimal_std::Env;
use cosmwasm_minimal_std::Event;
use cosmwasm_minimal_std::MessageInfo;
use cosmwasm_minimal_std::SystemResult;
use cosmwasm_vm::executor::AllocateInput;
use cosmwasm_vm::executor::AsFunctionName;
use cosmwasm_vm::executor::CosmwasmCallInput;
use cosmwasm_vm::executor::CosmwasmCallWithoutInfoInput;
use cosmwasm_vm::executor::DeallocateInput;
use cosmwasm_vm::executor::ExecutorError;
use cosmwasm_vm::executor::Unit;
use cosmwasm_vm::has::Has;
use cosmwasm_vm::memory::MemoryReadError;
use cosmwasm_vm::memory::MemoryWriteError;
use cosmwasm_vm::memory::Pointable;
use cosmwasm_vm::memory::PointerOf;
use cosmwasm_vm::memory::ReadWriteMemory;
use cosmwasm_vm::memory::ReadableMemory;
use cosmwasm_vm::memory::ReadableMemoryErrorOf;
use cosmwasm_vm::memory::WritableMemory;
use cosmwasm_vm::memory::WritableMemoryErrorOf;
use cosmwasm_vm::system::CosmwasmContractMeta;
use cosmwasm_vm::system::SystemError;
use cosmwasm_vm::tagged::Tagged;
use cosmwasm_vm::transaction::Transactional;
use cosmwasm_vm::transaction::TransactionalErrorOf;
use cosmwasm_vm::vm::*;
use either::Either;
use wasmi::CanResume;
use wasmi::Externals;
use wasmi::FuncInstance;
use wasmi::ImportResolver;
use wasmi::NopExternals;
use wasmi::RuntimeValue;

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
    + VMBase<CodeId = CosmwasmContractMeta, StorageKey = Vec<u8>, StorageValue = Vec<u8>>
    + ReadWriteMemory<Pointer = u32>
    + Transactional
    + Has<Env>
    + Has<MessageInfo>
    + Has<BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<Self>>>
where
    VmAddressOf<Self>:
        Clone + TryFrom<Addr, Error = VmErrorOf<Self>> + TryFrom<String, Error = VmErrorOf<Self>>,
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
        + CanResume,
    ReadableMemoryErrorOf<Self>: From<MemoryReadError>,
    WritableMemoryErrorOf<Self>: From<MemoryWriteError>;

pub trait WasmiModuleExecutor: Sized {
    fn executing_module(&self) -> WasmiModule;
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
        <Self as Has<BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<T>>>>::get(self)
            .get(&WasmiHostFunctionIndex(index))
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
            WasmiFunctionName(AllocateInput::<u32>::name().into()),
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
            WasmiFunctionName(DeallocateInput::<u32>::name().into()),
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
            WasmiFunctionName(I::name().into()),
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
            WasmiFunctionName(I::name().into()),
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
        self.0.charge(VmGas::RawCall)?;
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
    type CodeId = VmCodeIdOf<T>;
    type Address = VmAddressOf<T>;
    type StorageKey = VmStorageKeyOf<T>;
    type StorageValue = VmStorageValueOf<T>;
    type Error = VmErrorOf<T>;

    fn new_contract(&mut self, code_id: Self::CodeId) -> Result<Self::Address, Self::Error> {
        self.charge(VmGas::NewContract)?;
        self.0.new_contract(code_id)
    }

    fn set_code_id(
        &mut self,
        address: Self::Address,
        new_code_id: Self::CodeId,
    ) -> Result<(), Self::Error> {
        self.charge(VmGas::SetCodeId)?;
        self.0.set_code_id(address, new_code_id)
    }

    fn code_id(&mut self, address: Self::Address) -> Result<Self::CodeId, Self::Error> {
        self.charge(VmGas::GetCodeId)?;
        self.0.code_id(address)
    }

    fn query_continuation(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<cosmwasm_minimal_std::QueryResult, Self::Error> {
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
        self.charge(VmGas::ContinueExecute)?;
        self.0
            .continue_execute(address, funds, message, event_handler)
    }

    fn continue_instantiate(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.charge(VmGas::ContinueInstantiate)?;
        self.0
            .continue_instantiate(address, funds, message, event_handler)
    }

    fn continue_migrate(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.charge(VmGas::ContinueMigrate)?;
        self.0
            .continue_migrate(address, funds, message, event_handler)
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
        self.charge(VmGas::Transfer)?;
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

#[allow(dead_code)]
pub mod host_functions {
    use super::*;
    use cosmwasm_minimal_std::QueryRequest;
    use cosmwasm_vm::{
        executor::{constants, marshall_out, passthrough_in, passthrough_out, ConstantReadLimit},
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
                (
                    WasmiFunctionName("db_scan".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0004),
                        env_db_scan::<T> as WasmiHostFunction<T>,
                    ),
                ),
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
                    WasmiFunctionName("secp256k1_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000A),
                        env_secp256k1_batch_verify::<T> as WasmiHostFunction<T>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_recover_pubkey".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000B),
                        env_secp256k1_recove_pubkey::<T> as WasmiHostFunction<T>,
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
        log::debug!("db_read");
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

    fn env_db_scan<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("db_scan");
        Ok(None)
    }

    fn env_db_next<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("db_next");
        Ok(None)
    }

    fn env_addr_validate<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("addr_validate");
        Ok(Some(RuntimeValue::I32(0)))
    }

    fn env_addr_canonicalize<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("addr_canonicalize");
        Ok(None)
    }

    fn env_addr_humanize<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("addr_humanize");
        Ok(None)
    }

    fn env_secp256k1_verify<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("secp256k1_verify");
        Ok(None)
    }

    fn env_secp256k1_batch_verify<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("secp256k1_batch_verify");
        Ok(None)
    }

    fn env_secp256k1_recove_pubkey<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("secp256k1_recove_pubkey");
        Ok(None)
    }

    fn env_ed25519_verify<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("ed25519_verify");
        Ok(None)
    }

    fn env_ed25519_batch_verify<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("ed25519_batch_verify");
        Ok(None)
    }

    fn env_debug<T>(
        _: &mut WasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, VmErrorOf<T>>
    where
        T: WasmiBaseVM,
    {
        log::debug!("debug");
        Ok(None)
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
                vm.charge(VmGas::QueryChain)?;
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
