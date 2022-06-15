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
use crate::executor::Executor;
use crate::executor::ExecutorError;
use crate::executor::ExecutorPointer;
use crate::host::Host;
use crate::loader::Loader;
use crate::loader::LoaderCodeIdOf;
use crate::loader::LoaderErrorOf;
use crate::memory::MemoryReadError;
use crate::memory::MemoryWriteError;
use crate::memory::Pointable;
use crate::memory::ReadWriteMemory;
use crate::memory::ReadableMemory;
use crate::memory::WritableMemory;
use crate::system::System;
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
pub type WasmiHostFunction<T> =
    fn(&mut T, &[RuntimeValue]) -> Result<Option<RuntimeValue>, WasmiVMError>;
pub type WasmiHostModule<T> =
    BTreeMap<WasmiFunctionName, (WasmiHostFunctionIndex, WasmiHostFunction<T>)>;

#[derive(PartialEq, Eq, Debug)]
pub enum WasmiVMError {
    WasmiError(wasmi::Error),
    ExecutorError(ExecutorError),
    SystemError(SystemError),
    MemoryReadError(MemoryReadError),
    MemoryWriteError(MemoryWriteError),
    HostFunctionNotFound(WasmiHostFunctionIndex),
    HostFunctionFailure(String),
    ModuleNotFound,
    MemoryNotExported,
    MemoryExportedIsNotMemory,
    LowLevelMemoryReadError,
    LowLevelMemoryWriteError,
    InvalidPointer,
    UnexpectedUnit,
    StorageKeyNotFound(Vec<u8>),
    CodeNotFound(u64),
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
impl Display for WasmiVMError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl HostError for WasmiVMError {}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct AsWasmiVM<T>(T);

pub trait IsWasmiVM<T>:
    WasmiHost
    + HasExtension
    + for<'x> From<(
        <Self as HasExtension>::Extension<'x>,
        WasmiImportResolver<AsWasmiVM<T>>,
        WasmiModule,
    )>
{
    fn host_functions_definitions(
        &self,
    ) -> &BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<T>>>;
    fn host_functions(&self) -> &BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<AsWasmiVM<T>>>;
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

pub struct WasmiImportResolver<T>(BTreeMap<WasmiModuleName, WasmiHostModule<T>>);
impl<T> ImportResolver for WasmiImportResolver<T> {
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

pub struct WasmiOutput<'a>(Either<&'a wasmi::MemoryRef, (&'a wasmi::MemoryRef, RuntimeValue)>);

pub struct WasmiInput<'a>(WasmiFunctionName, WasmiFunctionArgs<'a>);

#[derive(Clone)]
pub struct WasmiModule {
    module: wasmi::ModuleRef,
    memory: wasmi::MemoryRef,
}

impl Pointable for wasmi::MemoryRef {
    type Pointer = u32;
}

impl ReadableMemory for wasmi::MemoryRef {
    type Error = WasmiVMError;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.get_into(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryReadError)
    }
}

impl WritableMemory for wasmi::MemoryRef {
    type Error = WasmiVMError;
    fn write(&self, offset: Self::Pointer, buffer: &[u8]) -> Result<(), Self::Error> {
        self.set(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryWriteError)
    }
}

impl ReadWriteMemory for wasmi::MemoryRef {}

impl<'a> TryFrom<WasmiOutput<'a>> for RuntimeValue {
    type Error = WasmiVMError;
    fn try_from(WasmiOutput(value): WasmiOutput<'a>) -> Result<Self, Self::Error> {
        match value {
            Either::Left(_) => Err(WasmiVMError::UnexpectedUnit),
            Either::Right((_, rt_value)) => Ok(rt_value),
        }
    }
}

impl<'a> TryFrom<WasmiOutput<'a>> for u32 {
    type Error = WasmiVMError;
    fn try_from(WasmiOutput(value): WasmiOutput<'a>) -> Result<Self, Self::Error> {
        match value {
            Either::Right((_, RuntimeValue::I32(rt_value))) => Ok(rt_value as u32),
            _ => Err(WasmiVMError::UnexpectedUnit),
        }
    }
}

impl<'a> TryFrom<AllocateInput<u32>> for WasmiInput<'a> {
    type Error = WasmiVMError;
    fn try_from(AllocateInput(ptr): AllocateInput<u32>) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName("allocate".to_owned()),
            (vec![RuntimeValue::I32(ptr as i32)], PhantomData),
        ))
    }
}

impl<'a> TryFrom<CosmwasmQueryInput<'a, u32>> for WasmiInput<'a> {
    type Error = WasmiVMError;
    fn try_from(
        CosmwasmQueryInput(Tagged(env_ptr, _), Tagged(msg_ptr, _)): CosmwasmQueryInput<'a, u32>,
    ) -> Result<Self, Self::Error> {
        Ok(WasmiInput(
            WasmiFunctionName("query".to_owned()),
            (
                vec![
                    RuntimeValue::I32(env_ptr as i32),
                    RuntimeValue::I32(msg_ptr as i32),
                ],
                PhantomData,
            ),
        ))
    }
}

impl<'a, I> TryFrom<CosmwasmCallInput<'a, u32, I>> for WasmiInput<'a>
where
    I: AsFunctionName,
{
    type Error = WasmiVMError;
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
        ))
    }
}

pub trait WasmiHost: Host<Key = Vec<u8>, Value = Vec<u8>, Error = WasmiVMError> {}

pub trait HasExtension {
    type Extension<'a>;
    fn extension<'a>(&mut self) -> Self::Extension<'a>;
}

pub type WasmiCodeOf<'a, T> = (WasmiImportResolver<T>, &'a [u8]);

impl<T> VM for AsWasmiVM<T>
where
    T: 'static + IsWasmiVM<T>,
{
    type Input<'a> = WasmiInput<'a>;
    type Output<'a> = WasmiOutput<'a>;
    type Error = WasmiVMError;
    type Code<'a> = WasmiCodeOf<'a, Self>;
    type Extension<'a> = T::Extension<'a>;
    fn new<'a>(
        (resolver, code): Self::Code<'a>,
        extension: Self::Extension<'a>,
    ) -> Result<Self, Self::Error> {
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
        Ok(AsWasmiVM(
            (
                extension,
                resolver,
                WasmiModule {
                    module: module_instance,
                    memory,
                },
            )
                .into(),
        ))
    }
    fn raw_call<'a, O, E>(
        &mut self,
        WasmiInput(WasmiFunctionName(function_name), (function_args, _)): Self::Input<'a>,
    ) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::Output<'x>, Error = E>,
        Self::Error: From<E>,
    {
        let WasmiModule { module, memory } = self.0.module();
        let value = module.invoke_export(&function_name, &function_args, self)?;
        Ok(O::try_from(WasmiOutput(match value {
            Some(non_unit) => Either::Right((&memory, non_unit)),
            None => Either::Left(&memory),
        }))?)
    }

    fn extension<'a>(&mut self) -> Self::Extension<'a> {
        self.0.extension()
    }
}

impl<T> ExecutorPointer<AsWasmiVM<T>> for u32 where T: 'static + IsWasmiVM<T> {}
impl<T> Executor for AsWasmiVM<T>
where
    T: 'static + IsWasmiVM<T>,
{
    type Pointer = u32;
    type Memory<'a> = wasmi::MemoryRef;
    fn memory<'a>(&mut self) -> Self::Memory<'a> {
        self.0.module().memory.clone()
    }
}

impl<T> Transactional for AsWasmiVM<T>
where
    T: 'static + IsWasmiVM<T> + Transactional,
    VmErrorOf<Self>: From<TransactionalErrorOf<T>>,
{
    type Error = TransactionalErrorOf<T>;
    fn transaction_begin(&mut self) -> Result<(), Self::Error> {
        self.0.transaction_begin()
    }
    fn transaction_commit(&mut self) -> Result<(), Self::Error> {
        self.0.transaction_commit()
    }
    fn transaction_abort(&mut self) -> Result<(), Self::Error> {
        self.0.transaction_abort()
    }
}

impl<T> Loader for AsWasmiVM<T>
where
    T: 'static + IsWasmiVM<T> + Loader<Output = Self>,
    VmErrorOf<Self>: From<LoaderErrorOf<T>>,
{
    type CodeId = LoaderCodeIdOf<T>;
    type Error = LoaderErrorOf<T>;
    type Output = Self;
    fn load(&mut self, code_id: Self::CodeId) -> Result<Self, Self::Error> {
        self.0.load(code_id)
    }
}

impl<T> System for AsWasmiVM<T>
where
    T: 'static + IsWasmiVM<T> + Transactional + Loader<Output = Self>,
    for<'x> VmErrorOf<Self>: From<TransactionalErrorOf<T>> + From<LoaderErrorOf<T>>,
    for<'x> u64: From<LoaderCodeIdOf<T>>,
{
}

#[allow(dead_code)]
mod host_functions {
    use super::*;
    use crate::executor::{constants, ConstantReadLimit};

    pub fn definitions<T>() -> BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<T>>>
    where
        T: 'static + IsWasmiVM<T>,
    {
        BTreeMap::from([(
            WasmiModuleName("env".to_owned()),
            BTreeMap::from([
                (
                    WasmiFunctionName("db_read".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0001),
                        env_db_read::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_write".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0002),
                        env_db_write::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_remove".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0003),
                        env_db_remove::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_scan".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0004),
                        env_db_scan::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_next".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0005),
                        env_db_next::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_validate".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0006),
                        env_addr_validate::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_canonicalize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0007),
                        env_addr_canonicalize::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_humanize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0008),
                        env_addr_humanize::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0009),
                        env_secp256k1_verify::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000A),
                        env_secp256k1_batch_verify::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_recover_pubkey".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000B),
                        env_secp256k1_recove_pubkey::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000C),
                        env_ed25519_verify::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000D),
                        env_ed25519_batch_verify::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("debug".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000E),
                        env_debug::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
                (
                    WasmiFunctionName("query_chain".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000F),
                        env_query_chain::<T> as WasmiHostFunction<AsWasmiVM<T>>,
                    ),
                ),
            ]),
        )])
    }

    fn env_db_read<T>(
        vm: &mut AsWasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError>
    where
        T: IsWasmiVM<T> + 'static,
    {
        log::debug!("db_read");
        match &values[..] {
            [RuntimeValue::I32(key_pointer)] => {
                let key = vm
                    .passthrough_out::<ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>>(
                        *key_pointer as u32,
                    )?;
                let value = vm.0.db_read(key)?;
                let Tagged(value_pointer, _) = vm.passthrough_in::<()>(&value)?;
                Ok(Some(RuntimeValue::I32(value_pointer as i32)))
            }
            _ => Err(WasmiVMError::InvalidHostSignature),
        }
    }

    fn env_db_write<T>(
        vm: &mut AsWasmiVM<T>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError>
    where
        T: IsWasmiVM<T> + 'static,
    {
        log::debug!("db_write");
        match &values[..] {
            [RuntimeValue::I32(key_pointer), RuntimeValue::I32(value_pointer)] => {
                let key = vm
                    .passthrough_out::<ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>>(
                        *key_pointer as u32,
                    )?;
                let value = vm
                    .passthrough_out::<ConstantReadLimit<{ constants::MAX_LENGTH_DB_VALUE }>>(
                        *value_pointer as u32,
                    )?;
                vm.0.db_write(key, value)?;
                Ok(None)
            }
            _ => Err(WasmiVMError::InvalidHostSignature),
        }
    }

    fn env_db_remove<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_remove");
        Ok(None)
    }

    fn env_db_scan<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_scan");
        Ok(None)
    }

    fn env_db_next<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_next");
        Ok(None)
    }

    fn env_addr_validate<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("addr_validate");
        Ok(None)
    }

    fn env_addr_canonicalize<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("addr_canonicalize");
        Ok(None)
    }

    fn env_addr_humanize<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("addr_humanize");
        Ok(None)
    }

    fn env_secp256k1_verify<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("secp256k1_verify");
        Ok(None)
    }

    fn env_secp256k1_batch_verify<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("secp256k1_batch_verify");
        Ok(None)
    }

    fn env_secp256k1_recove_pubkey<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("secp256k1_recove_pubkey");
        Ok(None)
    }

    fn env_ed25519_verify<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("ed25519_verify");
        Ok(None)
    }

    fn env_ed25519_batch_verify<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("ed25519_batch_verify");
        Ok(None)
    }

    fn env_debug<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("debug");
        Ok(None)
    }

    fn env_query_chain<T>(
        _: &mut AsWasmiVM<T>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("query_chain");
        Ok(None)
    }
}

pub fn new_vm<'a, T>(
    code: &'a [u8],
    extension: T::Extension<'a>,
) -> Result<AsWasmiVM<T>, WasmiVMError>
where
    T: 'static + IsWasmiVM<T> + WasmiHost,
{
    <AsWasmiVM<T>>::new(
        (
            WasmiImportResolver(host_functions::definitions::<T>()),
            code,
        ),
        extension,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::InstantiateInput;
    use core::assert_matches::assert_matches;
    use cosmwasm_minimal_std::{
        Addr, Binary, BlockInfo, ContractInfo, CosmwasmExecutionResult, CosmwasmQueryResult, Env,
        InstantiateResult, MessageInfo, QueryResult, Timestamp,
    };

    #[derive(Clone, Debug)]
    struct SimpleWasmiVMExtension {
        storage: BTreeMap<Vec<u8>, Vec<u8>>,
        codes: BTreeMap<u64, Vec<u8>>,
    }

    #[derive(Clone)]
    struct SimpleWasmiVM {
        host_functions_definitions: BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<Self>>>,
        host_functions: BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<AsWasmiVM<Self>>>,
        executing_module: WasmiModule,
        extension: SimpleWasmiVMExtension,
    }

    impl<'a>
        From<(
            <SimpleWasmiVM as HasExtension>::Extension<'a>,
            WasmiImportResolver<AsWasmiVM<SimpleWasmiVM>>,
            WasmiModule,
        )> for SimpleWasmiVM
    {
        fn from(
            (extension, WasmiImportResolver(host_functions_definitions), executing_module): (
                <SimpleWasmiVM as HasExtension>::Extension<'a>,
                WasmiImportResolver<AsWasmiVM<SimpleWasmiVM>>,
                WasmiModule,
            ),
        ) -> Self {
            SimpleWasmiVM {
                host_functions_definitions: host_functions_definitions.clone(),
                host_functions: host_functions_definitions
                    .clone()
                    .into_iter()
                    .map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
                    .flatten()
                    .collect(),
                executing_module,
                extension,
            }
        }
    }

    impl IsWasmiVM<SimpleWasmiVM> for SimpleWasmiVM {
        fn host_functions_definitions(
            &self,
        ) -> &BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<SimpleWasmiVM>>> {
            &self.host_functions_definitions
        }

        fn host_functions(
            &self,
        ) -> &BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>>
        {
            &self.host_functions
        }

        fn module(&self) -> WasmiModule {
            self.executing_module.clone()
        }
    }

    impl HasExtension for SimpleWasmiVM {
        type Extension<'a> = SimpleWasmiVMExtension;
        fn extension<'a>(&mut self) -> Self::Extension<'a> {
            self.extension.clone()
        }
    }

    impl Host for SimpleWasmiVM {
        type Key = Vec<u8>;
        type Value = Vec<u8>;
        type Error = WasmiVMError;
        fn db_read(&mut self, key: Self::Key) -> Result<Self::Value, Self::Error> {
            self.extension
                .storage
                .get(&key)
                .ok_or(WasmiVMError::StorageKeyNotFound(key))
                .cloned()
        }
        fn db_write(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
            self.extension.storage.insert(key, value);
            Ok(())
        }
    }

    impl WasmiHost for SimpleWasmiVM {}

    impl Loader for SimpleWasmiVM {
        type CodeId = u64;
        type Output = AsWasmiVM<Self>;
        type Error = WasmiVMError;
        fn load(&mut self, code_id: Self::CodeId) -> Result<Self::Output, Self::Error> {
            let code = self
                .extension
                .codes
                .get(&code_id)
                .cloned()
                .ok_or(WasmiVMError::CodeNotFound(code_id))?;
            let input = (
                WasmiImportResolver(self.host_functions_definitions.clone()),
                code.as_ref(),
            );
            // reset storage for next execution
            let SimpleWasmiVMExtension { codes, .. } = self.extension();
            AsWasmiVM::<SimpleWasmiVM>::new(
                input,
                SimpleWasmiVMExtension {
                    storage: Default::default(),
                    codes,
                },
            )
        }
    }

    #[test]
    fn test() {
        env_logger::builder().init();
        let execute_vm = |mut vm: AsWasmiVM<SimpleWasmiVM>| {
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
                vm.cosmwasm_call::<InstantiateInput>(
                    env.clone(),
                    info.clone(),
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
                vm.cosmwasm_query(
                    Env {
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
                    r#"{ "token_info": {} }"#.as_bytes(),
                )
                .unwrap(),
                QueryResult(CosmwasmQueryResult::Ok(Binary(
                    r#"{"name":"Picasso","symbol":"PICA","decimals":12,"total_supply":"0"}"#
                        .as_bytes()
                        .to_vec()
                )))
            );
        };
        let code = include_bytes!("../../fixtures/cw20_base.wasm").to_vec();
        let mut vm = new_vm::<SimpleWasmiVM>(
            &code,
            SimpleWasmiVMExtension {
                storage: Default::default(),
                codes: BTreeMap::from([(0x1337, code.clone())]),
            },
        )
        .unwrap();
        let vm2 = vm.load(0x1337).unwrap();
        let vm3 = vm.load(0x1337).unwrap();
        execute_vm(vm);
        execute_vm(vm2);
        execute_vm(vm3);
    }
}
