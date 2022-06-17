// wasmi.rs ---

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

use crate::executor::AllocateInput;
use crate::executor::AsFunctionName;
use crate::executor::CosmwasmCallInput;
use crate::executor::CosmwasmQueryInput;
use crate::executor::DeallocateInput;
use crate::executor::ExecutorError;
use crate::executor::Unit;
use crate::has::Has;
use crate::host::Host;
use crate::loader::Loader;
use crate::loader::LoaderCodeIdOf;
use crate::loader::LoaderErrorOf;
use crate::loader::LoaderOutputOf;
use crate::memory::MemoryReadError;
use crate::memory::MemoryWriteError;
use crate::memory::Pointable;
use crate::memory::ReadWriteMemory;
use crate::memory::ReadableMemory;
use crate::memory::WritableMemory;
use crate::system::Bank;
use crate::system::CosmwasmCodeId;
use crate::system::Peripherals;
use crate::system::SystemError;
use crate::tagged::Tagged;
use crate::transaction::Transactional;
use crate::transaction::TransactionalErrorOf;
use crate::vm::*;
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::BorrowError;
use core::cell::BorrowMutError;
use core::fmt::Debug;
use core::fmt::Display;
use core::marker::PhantomData;
use core::num::TryFromIntError;
use either::Either;
use wasmi::Externals;
use wasmi::FuncInstance;
use wasmi::HostError;
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
pub type WasmiHostFunction<T, E> = fn(&mut T, &[RuntimeValue]) -> Result<Option<RuntimeValue>, E>;
pub type WasmiHostModule<T, E> =
    BTreeMap<WasmiFunctionName, (WasmiHostFunctionIndex, WasmiHostFunction<T, E>)>;

#[derive(PartialEq, Eq, Debug)]
pub enum WasmiVMError {
    WasmiError(wasmi::Error),
    ExecutorError(ExecutorError),
    SystemError(SystemError),
    MemoryReadError(MemoryReadError),
    MemoryWriteError(MemoryWriteError),
    BorrowError,
    BorrowMutError,
    HostFunctionNotFound(WasmiHostFunctionIndex),
    HostFunctionFailure(String),
    ModuleNotFound,
    MemoryNotExported,
    MemoryExportedIsNotMemory,
    LowLevelMemoryReadError,
    LowLevelMemoryWriteError,
    InvalidPointer,
    UnexpectedUnit,
    ExpectedUnit,
    StorageKeyNotFound(Vec<u8>),
    CodeNotFound(CosmwasmCodeId),
    InvalidHostSignature,
}
impl From<wasmi::Error> for WasmiVMError {
    fn from(e: wasmi::Error) -> Self {
        WasmiVMError::WasmiError(e)
    }
}
impl From<wasmi::Trap> for WasmiVMError {
    fn from(e: wasmi::Trap) -> Self {
        wasmi::Error::from(e).into()
    }
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
impl From<BorrowError> for WasmiVMError {
    fn from(_: BorrowError) -> Self {
        WasmiVMError::BorrowError
    }
}
impl From<BorrowMutError> for WasmiVMError {
    fn from(_: BorrowMutError) -> Self {
        WasmiVMError::BorrowMutError
    }
}
impl Display for WasmiVMError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl HostError for WasmiVMError {}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct AsWasmiVM<T>(T);

pub type IsWasmiVMErrorOf<T> = <T as IsWasmiVM<T>>::Error;

pub trait IsWasmiVM<T>: WasmiHost {
    type Error: Debug
        + From<WasmiVMError>
        + From<MemoryReadError>
        + From<MemoryWriteError>
        + From<ExecutorError>
        + From<SystemError>
        + From<<Self as Host>::Error>
        + HostError;
    fn host_functions_definitions(
        &self,
    ) -> &BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<T>, <Self as IsWasmiVM<T>>::Error>>;
    fn host_functions(
        &self,
    ) -> &BTreeMap<
        WasmiHostFunctionIndex,
        WasmiHostFunction<AsWasmiVM<T>, <Self as IsWasmiVM<T>>::Error>,
    >;
    fn module(&self) -> WasmiModule;
}

impl<T> Externals for AsWasmiVM<T>
where
    T: IsWasmiVM<T>,
{
    fn invoke_index(
        &mut self,
        index: usize,
        args: wasmi::RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, wasmi::Trap> {
        Ok((self
            .0
            .host_functions()
            .get(&WasmiHostFunctionIndex(index))
            .ok_or(WasmiVMError::HostFunctionNotFound(
                WasmiHostFunctionIndex(index),
            ))?)(self, args.as_ref())?)
    }
}

pub struct WasmiImportResolver<T, E>(BTreeMap<WasmiModuleName, WasmiHostModule<T, E>>);
impl<T, E> ImportResolver for WasmiImportResolver<T, E> {
    fn resolve_func(
        &self,
        module_name: &str,
        field_name: &str,
        signature: &wasmi::Signature,
    ) -> Result<wasmi::FuncRef, wasmi::Error> {
        let module = self.0.get(&WasmiModuleName(module_name.to_owned())).ok_or(
            wasmi::Error::Instantiation(format!(
                "A module tried to load an unknown host module: {}",
                module_name
            )),
        )?;
        let (WasmiHostFunctionIndex(function_index), _) = *module
            .get(&WasmiFunctionName(field_name.to_owned()))
            .ok_or(wasmi::Error::Instantiation(format!(
                "A module tried to load an unknown host function: {}.{}",
                module_name, field_name
            )))?;
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
    module: wasmi::ModuleRef,
    memory: wasmi::MemoryRef,
}

impl<'a, T> TryFrom<WasmiOutput<'a, T>> for RuntimeValue
where
    T: IsWasmiVM<T>,
{
    type Error = IsWasmiVMErrorOf<T>;
    fn try_from(WasmiOutput(value, _): WasmiOutput<'a, T>) -> Result<Self, Self::Error> {
        match value {
            Either::Right((_, rt_value)) => Ok(rt_value),
            _ => Err(WasmiVMError::UnexpectedUnit.into()),
        }
    }
}

impl<'a, T> TryFrom<WasmiOutput<'a, T>> for Unit
where
    T: IsWasmiVM<T>,
{
    type Error = IsWasmiVMErrorOf<T>;
    fn try_from(WasmiOutput(value, _): WasmiOutput<'a, T>) -> Result<Self, Self::Error> {
        match value {
            Either::Left(_) => Ok(Unit),
            _ => Err(WasmiVMError::UnexpectedUnit.into()),
        }
    }
}

impl<'a, T> TryFrom<WasmiOutput<'a, T>> for u32
where
    T: IsWasmiVM<T>,
{
    type Error = IsWasmiVMErrorOf<T>;
    fn try_from(WasmiOutput(value, _): WasmiOutput<'a, T>) -> Result<Self, Self::Error> {
        match value {
            Either::Right((_, RuntimeValue::I32(rt_value))) => Ok(rt_value as u32),
            _ => Err(WasmiVMError::UnexpectedUnit.into()),
        }
    }
}

impl<'a, T> TryFrom<AllocateInput<u32>> for WasmiInput<'a, T>
where
    T: IsWasmiVM<T>,
{
    type Error = IsWasmiVMErrorOf<T>;
    fn try_from(AllocateInput(ptr): AllocateInput<u32>) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName(AllocateInput::<u32>::name().into()),
            (vec![RuntimeValue::I32(ptr as i32)], PhantomData),
            PhantomData,
        ))
    }
}

impl<'a, T> TryFrom<DeallocateInput<u32>> for WasmiInput<'a, T>
where
    T: IsWasmiVM<T>,
{
    type Error = IsWasmiVMErrorOf<T>;
    fn try_from(DeallocateInput(ptr): DeallocateInput<u32>) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName(DeallocateInput::<u32>::name().into()),
            (vec![RuntimeValue::I32(ptr as i32)], PhantomData),
            PhantomData,
        ))
    }
}

impl<'a, T> TryFrom<CosmwasmQueryInput<'a, u32>> for WasmiInput<'a, T>
where
    T: IsWasmiVM<T>,
{
    type Error = IsWasmiVMErrorOf<T>;
    fn try_from(
        CosmwasmQueryInput(Tagged(env_ptr, _), Tagged(msg_ptr, _)): CosmwasmQueryInput<'a, u32>,
    ) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName(CosmwasmQueryInput::<u32>::name().into()),
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

impl<'a, I, T> TryFrom<CosmwasmCallInput<'a, u32, I>> for WasmiInput<'a, T>
where
    T: IsWasmiVM<T>,
    I: AsFunctionName,
{
    type Error = IsWasmiVMErrorOf<T>;
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

pub trait WasmiHost: Host<Key = Vec<u8>, Value = Vec<u8>> {}

impl<T: Has<U>, U> Has<U> for AsWasmiVM<T> {
    fn get(&self) -> U {
        self.0.get()
    }
}

impl<T> AsWasmiVM<T>
where
    T: IsWasmiVM<T>,
{
    pub fn new(
        resolver: WasmiImportResolver<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
        code: &[u8],
    ) -> Result<
        (
            WasmiImportResolver<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
            &[u8],
            WasmiModule,
        ),
        WasmiVMError,
    > {
        let wasmi_module = wasmi::Module::from_buffer(code)?;
        let not_started_module_instance = wasmi::ModuleInstance::new(&wasmi_module, &resolver)?;
        let module_instance = not_started_module_instance.run_start(&mut NopExternals)?;
        let memory_exported = module_instance
            .export_by_name("memory")
            .ok_or(WasmiVMError::MemoryNotExported)?;
        let memory = match memory_exported {
            wasmi::ExternVal::Memory(mem) => Ok(mem),
            _ => Err(WasmiVMError::MemoryExportedIsNotMemory),
        }?;
        Ok((
            resolver,
            code,
            WasmiModule {
                module: module_instance,
                memory,
            },
        ))
    }
}

impl<T> VM for AsWasmiVM<T>
where
    T: IsWasmiVM<T>,
{
    type Input<'a> = WasmiInput<'a, T>;
    type Output<'a> = WasmiOutput<'a, T>;
    type Error = <T as IsWasmiVM<T>>::Error;
    fn raw_call<'a, O>(
        &mut self,
        WasmiInput(WasmiFunctionName(function_name), (function_args, _), _): Self::Input<'a>,
    ) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::Output<'x>, Error = VmErrorOf<Self>>,
    {
        let WasmiModule { module, memory } = self.0.module();
        let value = module
            .invoke_export(&function_name, &function_args, self)
            .map_err(WasmiVMError::WasmiError)?;
        Ok(O::try_from(WasmiOutput(
            match value {
                Some(non_unit) => Either::Right((&memory, non_unit)),
                None => Either::Left(&memory),
            },
            PhantomData,
        ))?)
    }
}

impl<T> Pointable for AsWasmiVM<T> {
    type Pointer = u32;
}

impl<T> ReadableMemory for AsWasmiVM<T>
where
    T: IsWasmiVM<T>,
{
    type Error = IsWasmiVMErrorOf<T>;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.0
            .module()
            .memory
            .get_into(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryReadError.into())
    }
}

impl<T> WritableMemory for AsWasmiVM<T>
where
    T: IsWasmiVM<T>,
{
    type Error = IsWasmiVMErrorOf<T>;
    fn write(&self, offset: Self::Pointer, buffer: &[u8]) -> Result<(), Self::Error> {
        self.0
            .module()
            .memory
            .set(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryWriteError.into())
    }
}

impl<T> ReadWriteMemory for AsWasmiVM<T> where T: IsWasmiVM<T> {}

impl<T> Transactional for AsWasmiVM<T>
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

impl<T> Loader for AsWasmiVM<T>
where
    T: Loader,
{
    type CodeId = LoaderCodeIdOf<T>;
    type Error = LoaderErrorOf<T>;
    type Output = LoaderOutputOf<T>;
    fn load(&mut self, code_id: Self::CodeId) -> Result<Self::Output, Self::Error> {
        self.0.load(code_id)
    }
}

impl<T> Bank for AsWasmiVM<T>
where
    T: Bank,
{
    type AccountId = T::AccountId;
    type Error = T::Error;
    fn transfer(
        &mut self,
        from: &Self::AccountId,
        to: &Self::AccountId,
        funds: &[cosmwasm_minimal_std::Coin],
    ) -> Result<(), Self::Error> {
        self.0.transfer(from, to, funds)
    }
}

impl<T> Peripherals for AsWasmiVM<T>
where
    T: Peripherals,
{
    type AccountId = T::AccountId;
    type CodeId = T::CodeId;
    type Error = T::Error;
    fn contract_code(&mut self, contract: &Self::AccountId) -> Result<Self::CodeId, Self::Error> {
        self.0.contract_code(contract)
    }
}

#[allow(dead_code)]
mod host_functions {
    use super::*;
    use crate::executor::{constants, passthrough_in, passthrough_out, ConstantReadLimit};

    pub fn definitions<T>(
    ) -> BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>>
    where
        T: IsWasmiVM<T>,
        IsWasmiVMErrorOf<T>: From<ExecutorError>,
    {
        BTreeMap::from([(
            WasmiModuleName("env".to_owned()),
            BTreeMap::from([
                (
                    WasmiFunctionName("db_read".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0001),
                        env_db_read::<T> as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_write".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0002),
                        env_db_write::<T> as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_remove".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0003),
                        env_db_remove::<T> as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_scan".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0004),
                        env_db_scan::<T> as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_next".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0005),
                        env_db_next::<T> as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_validate".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0006),
                        env_addr_validate::<T>
                            as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_canonicalize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0007),
                        env_addr_canonicalize::<T>
                            as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_humanize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0008),
                        env_addr_humanize::<T>
                            as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0009),
                        env_secp256k1_verify::<T>
                            as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000A),
                        env_secp256k1_batch_verify::<T>
                            as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_recover_pubkey".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000B),
                        env_secp256k1_recove_pubkey::<T>
                            as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000C),
                        env_ed25519_verify::<T>
                            as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000D),
                        env_ed25519_batch_verify::<T>
                            as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("debug".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000E),
                        env_debug::<T> as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("query_chain".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000F),
                        env_query_chain::<T>
                            as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("abort".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0010),
                        env_abort::<T> as WasmiHostFunction<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>,
                    ),
                ),
            ]),
        )])
    }

    fn env_db_read<T>(
        vm: &mut AsWasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("db_read");
        match &values[..] {
            [RuntimeValue::I32(key_pointer)] => {
                let key = passthrough_out::<
                    AsWasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>,
                >(vm, *key_pointer as u32)?;
                let value = vm.0.db_read(key);
                match value {
                    Ok(Some(value)) => {
                        let Tagged(value_pointer, _) =
                            passthrough_in::<AsWasmiVM<T>, ()>(vm, &value)?;
                        Ok(Some(RuntimeValue::I32(value_pointer as i32)))
                    }
                    Ok(None) => Ok(Some(RuntimeValue::I32(0))),
                    Err(e) => Err(e.into()),
                }
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_db_write<T>(
        vm: &mut AsWasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("db_write");
        match &values[..] {
            [RuntimeValue::I32(key_pointer), RuntimeValue::I32(value_pointer)] => {
                let key = passthrough_out::<
                    AsWasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>,
                >(vm, *key_pointer as u32)?;
                let value = passthrough_out::<
                    AsWasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_DB_VALUE }>,
                >(vm, *value_pointer as u32)?;
                vm.0.db_write(key, value)?;
                Ok(None)
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }

    fn env_db_remove<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("db_remove");
        Ok(None)
    }

    fn env_db_scan<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("db_scan");
        Ok(None)
    }

    fn env_db_next<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("db_next");
        Ok(None)
    }

    fn env_addr_validate<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("addr_validate");
        Ok(Some(RuntimeValue::I32(0)))
    }

    fn env_addr_canonicalize<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("addr_canonicalize");
        Ok(None)
    }

    fn env_addr_humanize<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("addr_humanize");
        Ok(None)
    }

    fn env_secp256k1_verify<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("secp256k1_verify");
        Ok(None)
    }

    fn env_secp256k1_batch_verify<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("secp256k1_batch_verify");
        Ok(None)
    }

    fn env_secp256k1_recove_pubkey<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("secp256k1_recove_pubkey");
        Ok(None)
    }

    fn env_ed25519_verify<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("ed25519_verify");
        Ok(None)
    }

    fn env_ed25519_batch_verify<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("ed25519_batch_verify");
        Ok(None)
    }

    fn env_debug<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("debug");
        Ok(None)
    }

    fn env_query_chain<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
    {
        log::debug!("query_chain");
        Ok(None)
    }

    fn env_abort<T>(
        vm: &mut AsWasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, IsWasmiVMErrorOf<T>>
    where
        T: IsWasmiVM<T>,
        IsWasmiVMErrorOf<T>: From<ExecutorError>,
    {
        log::debug!("abort");
        match &values[..] {
            [RuntimeValue::I32(message_pointer)] => {
                let message: Vec<u8> = passthrough_out::<
                    AsWasmiVM<T>,
                    ConstantReadLimit<{ constants::MAX_LENGTH_ABORT }>,
                >(vm, *message_pointer as u32)?;
                vm.0.abort(String::from_utf8_lossy(&message).into())?;
                Ok(None)
            }
            _ => Err(WasmiVMError::InvalidHostSignature.into()),
        }
    }
}

pub fn new_vm<T, E>(
    code: &[u8],
    extension: E,
    f: impl FnOnce(WasmiImportResolver<AsWasmiVM<T>, IsWasmiVMErrorOf<T>>, &[u8], E, WasmiModule) -> T,
) -> Result<AsWasmiVM<T>, WasmiVMError>
where
    T: IsWasmiVM<T>,
    IsWasmiVMErrorOf<T>: From<ExecutorError>,
{
    let resolver = WasmiImportResolver(host_functions::definitions::<T>());
    let (resolver, code, module) = AsWasmiVM::<T>::new(resolver, code)?;
    Ok(AsWasmiVM(f(resolver, code, extension, module)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        executor::{cosmwasm_call, cosmwasm_query, ExecuteInput, InstantiateInput},
        system::{cosmwasm_system_entrypoint, LoadContract},
    };
    use alloc::rc::Rc;
    use core::{assert_matches::assert_matches, cell::RefCell};
    use cosmwasm_minimal_std::{
        Addr, Attribute, Binary, BlockInfo, ContractInfo, CosmwasmExecutionResult,
        CosmwasmQueryResult, Env, Event, InstantiateResult, MessageInfo, QueryResult, Timestamp,
    };

    struct SimpleWasmiVMExtension {
        storage: BTreeMap<Vec<u8>, Vec<u8>>,
        codes: BTreeMap<CosmwasmCodeId, Vec<u8>>,
    }

    struct SimpleWasmiVM {
        host_functions_definitions:
            BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<Self>, WasmiVMError>>,
        host_functions:
            BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<AsWasmiVM<Self>, WasmiVMError>>,
        executing_module: WasmiModule,
        load_info: LoadContract,
        extension: Rc<RefCell<SimpleWasmiVMExtension>>,
    }

    impl IsWasmiVM<SimpleWasmiVM> for SimpleWasmiVM {
        type Error = WasmiVMError;

        fn host_functions_definitions(
            &self,
        ) -> &BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<SimpleWasmiVM>, WasmiVMError>>
        {
            &self.host_functions_definitions
        }

        fn host_functions(
            &self,
        ) -> &BTreeMap<
            WasmiHostFunctionIndex,
            WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>, WasmiVMError>,
        > {
            &self.host_functions
        }

        fn module(&self) -> WasmiModule {
            self.executing_module.clone()
        }
    }

    impl Host for SimpleWasmiVM {
        type Key = Vec<u8>;
        type Value = Vec<u8>;
        type Error = WasmiVMError;
        fn db_read(&mut self, key: Self::Key) -> Result<Option<Self::Value>, Self::Error> {
            Ok(self.extension.try_borrow()?.storage.get(&key).cloned())
        }
        fn db_write(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
            self.extension.try_borrow_mut()?.storage.insert(key, value);
            Ok(())
        }

        fn abort(&mut self, message: String) -> Result<(), Self::Error> {
            log::debug!("Contract aborted: {}", message);
            Err(WasmiVMError::SystemError(
                SystemError::ContractExecutionFailure(message),
            ))
        }
    }

    impl WasmiHost for SimpleWasmiVM {}

    impl Loader for SimpleWasmiVM {
        type CodeId = LoadContract;
        type Error = WasmiVMError;
        type Output = AsWasmiVM<SimpleWasmiVM>;
        fn load(
            &mut self,
            LoadContract { env, info, code_id }: Self::CodeId,
        ) -> Result<Self::Output, Self::Error> {
            log::debug!("Load");
            let code = self
                .extension
                .borrow()
                .codes
                .get(&code_id)
                .cloned()
                .ok_or(WasmiVMError::CodeNotFound(code_id))?;
            new_vm(
                &code,
                self.extension.clone(),
                |WasmiImportResolver(host_functions_definitions), _, extension, module| {
                    SimpleWasmiVM {
                        host_functions_definitions: host_functions_definitions.clone(),
                        host_functions: host_functions_definitions
                            .clone()
                            .into_iter()
                            .map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
                            .flatten()
                            .collect(),
                        executing_module: module,
                        load_info: LoadContract { env, info, code_id },
                        extension,
                    }
                },
            )
        }
    }

    #[derive(Debug)]
    struct BankAccount(Addr);
    impl Bank for SimpleWasmiVM {
        type AccountId = BankAccount;
        type Error = WasmiVMError;
        fn transfer(
            &mut self,
            from: &Self::AccountId,
            to: &Self::AccountId,
            funds: &[cosmwasm_minimal_std::Coin],
        ) -> Result<(), Self::Error> {
            log::debug!("Transfer: {:?} -> {:?}\n{:?}", from, to, funds);
            Ok(())
        }
    }

    impl TryFrom<Addr> for BankAccount {
        type Error = WasmiVMError;
        fn try_from(value: Addr) -> Result<Self, Self::Error> {
            Ok(BankAccount(value))
        }
    }

    impl Has<Env> for SimpleWasmiVM {
        fn get(&self) -> Env {
            self.load_info.env.clone()
        }
    }
    impl Has<MessageInfo> for SimpleWasmiVM {
        fn get(&self) -> MessageInfo {
            self.load_info.info.clone()
        }
    }

    impl Transactional for SimpleWasmiVM {
        type Error = WasmiVMError;
        fn transaction_begin(&mut self) -> Result<(), Self::Error> {
            log::debug!("=== TX BEGIN ===");
            Ok(())
        }
        fn transaction_commit(&mut self) -> Result<(), Self::Error> {
            log::debug!("=== TX END ===");
            Ok(())
        }
        fn transaction_rollback(&mut self) -> Result<(), Self::Error> {
            log::debug!("=== TX ABORT ===");
            Ok(())
        }
    }

    impl Peripherals for SimpleWasmiVM {
        type AccountId = BankAccount;
        type CodeId = CosmwasmCodeId;
        type Error = WasmiVMError;
        fn contract_code(&mut self, _: &Self::AccountId) -> Result<Self::CodeId, Self::Error> {
            log::debug!("ContractCode");
            Ok(0x1337)
        }
    }

    #[test]
    fn test_bare() {
        let code = include_bytes!("../../fixtures/cw20_base.wasm").to_vec();
        let extension = Rc::new(RefCell::new(SimpleWasmiVMExtension {
            storage: Default::default(),
            codes: BTreeMap::from([(0x1337, code.clone())]),
        }));
        let mut vm = new_vm::<SimpleWasmiVM, _>(
            &code,
            extension,
            |WasmiImportResolver(host_functions_definitions), _, extension, module| SimpleWasmiVM {
                host_functions_definitions: host_functions_definitions.clone(),
                host_functions: host_functions_definitions
                    .clone()
                    .into_iter()
                    .map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
                    .flatten()
                    .collect(),
                executing_module: module,
                load_info: LoadContract {
                    env: Env {
                        block: BlockInfo {
                            height: 0,
                            time: Timestamp(0),
                            chain_id: "".into(),
                        },
                        transaction: None,
                        contract: ContractInfo {
                            address: Addr::unchecked(""),
                        },
                    },
                    info: MessageInfo {
                        sender: Addr::unchecked(""),
                        funds: Default::default(),
                    },
                    code_id: 0xDEADC0DE,
                },
                extension,
            },
        )
        .unwrap();
        let env = Env {
            block: BlockInfo {
                height: 0,
                time: Timestamp(0),
                chain_id: "".into(),
            },
            transaction: None,
            contract: ContractInfo {
                address: Addr::unchecked(""),
            },
        };
        let info = MessageInfo {
            sender: Addr::unchecked(""),
            funds: Default::default(),
        };
        assert_matches!(
            cosmwasm_call::<InstantiateInput, AsWasmiVM<SimpleWasmiVM>>(
                &mut vm,
                &env,
                &info,
                r#"{
                  "name": "Picasso",
                  "symbol": "PICA",
                  "decimals": 12,
                  "initial_balances": [],
                  "mint": null,
                  "marketing": null
                }"#
                .as_bytes(),
            )
            .unwrap(),
            InstantiateResult(CosmwasmExecutionResult::Ok(_))
        );
        assert_eq!(
            cosmwasm_query::<AsWasmiVM<SimpleWasmiVM>>(
                &mut vm,
                &env,
                r#"{ "token_info": {} }"#.as_bytes(),
            )
            .unwrap(),
            QueryResult(CosmwasmQueryResult::Ok(Binary(
                r#"{"name":"Picasso","symbol":"PICA","decimals":12,"total_supply":"0"}"#
                    .as_bytes()
                    .to_vec()
            )))
        );
    }

    #[test]
    fn test_orchestration_base() {
        env_logger::builder().init();
        let code = include_bytes!("../../fixtures/cw20_base.wasm").to_vec();
        let extension = Rc::new(RefCell::new(SimpleWasmiVMExtension {
            storage: Default::default(),
            codes: BTreeMap::from([(0x1337, code.clone())]),
        }));
        let mut vm = new_vm::<SimpleWasmiVM, _>(
            &code,
            extension,
            |WasmiImportResolver(host_functions_definitions), _, extension, module| SimpleWasmiVM {
                host_functions_definitions: host_functions_definitions.clone(),
                host_functions: host_functions_definitions
                    .clone()
                    .into_iter()
                    .map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
                    .flatten()
                    .collect(),
                executing_module: module,
                load_info: LoadContract {
                    env: Env {
                        block: BlockInfo {
                            height: 0,
                            time: Timestamp(0),
                            chain_id: "".into(),
                        },
                        transaction: None,
                        contract: ContractInfo {
                            address: Addr::unchecked(""),
                        },
                    },
                    info: MessageInfo {
                        sender: Addr::unchecked(""),
                        funds: Default::default(),
                    },
                    code_id: 0xDEADC0DE,
                },
                extension,
            },
        )
        .unwrap();
        assert_eq!(
            cosmwasm_system_entrypoint::<InstantiateInput, AsWasmiVM<SimpleWasmiVM>>(
                &mut vm,
                r#"{
                  "name": "Picasso",
                  "symbol": "PICA",
                  "decimals": 12,
                  "initial_balances": [],
                  "mint": {
                    "minter": "",
                    "cap": null
                  },
                  "marketing": null
                }"#
                .as_bytes(),
            )
            .unwrap(),
            (None, vec![])
        );

        assert_eq!(
            cosmwasm_system_entrypoint::<ExecuteInput, AsWasmiVM<SimpleWasmiVM>>(
                &mut vm,
                r#"{
                  "mint": {
                    "recipient": "0xCAFEBABE",
                    "amount": "5555"
                  }
                }"#
                .as_bytes(),
            )
            .unwrap(),
            (
                None,
                vec![Event::new(
                    "wasm".into(),
                    vec![
                        Attribute {
                            key: "action".into(),
                            value: "mint".into()
                        },
                        Attribute {
                            key: "to".into(),
                            value: "0xCAFEBABE".into()
                        },
                        Attribute {
                            key: "amount".into(),
                            value: "5555".into()
                        }
                    ]
                )]
            )
        );
    }

    #[test]
    fn test_orchestration_advanced() {
        let code = include_bytes!("../../fixtures/hackatom.wasm").to_vec();
        let extension = Rc::new(RefCell::new(SimpleWasmiVMExtension {
            storage: Default::default(),
            codes: BTreeMap::from([(0x1337, code.clone())]),
        }));
        let mut vm = new_vm::<SimpleWasmiVM, _>(
            &code,
            extension,
            |WasmiImportResolver(host_functions_definitions), _, extension, module| SimpleWasmiVM {
                host_functions_definitions: host_functions_definitions.clone(),
                host_functions: host_functions_definitions
                    .clone()
                    .into_iter()
                    .map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
                    .flatten()
                    .collect(),
                executing_module: module,
                load_info: LoadContract {
                    env: Env {
                        block: BlockInfo {
                            height: 0,
                            time: Timestamp(0),
                            chain_id: "".into(),
                        },
                        transaction: None,
                        contract: ContractInfo {
                            address: Addr::unchecked(""),
                        },
                    },
                    info: MessageInfo {
                        sender: Addr::unchecked(""),
                        funds: Default::default(),
                    },
                    code_id: 0xDEADC0DE,
                },
                extension,
            },
        )
        .unwrap();
        assert_eq!(
            cosmwasm_system_entrypoint::<ExecuteInput, AsWasmiVM<SimpleWasmiVM>>(
                &mut vm,
                r#"{
                  "message_loop": {}
                }"#
                .as_bytes(),
            )
            .unwrap(),
            (
                None,
                vec![Event::new(
                    "wasm".into(),
                    vec![
                        Attribute {
                            key: "action".into(),
                            value: "mint".into()
                        },
                        Attribute {
                            key: "to".into(),
                            value: "0xCAFEBABE".into()
                        },
                        Attribute {
                            key: "amount".into(),
                            value: "5555".into()
                        }
                    ]
                )]
            )
        );
    }
}
