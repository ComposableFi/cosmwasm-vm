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

use crate::executor::SimpleExecutorError;
use crate::memory::MemoryReadError;
use crate::memory::MemoryWriteError;
use crate::memory::Pointable;
use crate::memory::ReadWriteMemory;
use crate::memory::ReadableMemory;
use crate::memory::WritableMemory;
use crate::vm::*;
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WasmiModuleId(u32);
#[derive(PartialEq, Eq, Debug)]
pub enum WasmiVMError {
    WasmiError(wasmi::Error),
    WasmiModuleError(WasmiModuleError),
    ModuleNotFound,
    MemoryNotExported,
    MemoryExportedIsNotMemory,
    HostFunctionNotFound(WasmiHostFunctionIndex),
    HostFunctionFailure(String),
    ExecutorError(SimpleExecutorError),
    InvalidPointer,
}
impl From<WasmiModuleError> for WasmiVMError {
    fn from(e: WasmiModuleError) -> Self {
        WasmiVMError::WasmiModuleError(e)
    }
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
impl From<SimpleExecutorError> for WasmiVMError {
    fn from(e: SimpleExecutorError) -> Self {
        WasmiVMError::ExecutorError(e)
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

pub trait IsWasmiVM<T> {
    fn codes(&self) -> &BTreeMap<WasmiModuleId, Vec<u8>>;
    fn host_functions_definitions(&self) -> &BTreeMap<WasmiModuleName, WasmiHostModule<T>>;
    fn host_functions(&self) -> &BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<T>>;
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
            ))?)(&mut self.0, args.as_ref())?)
    }
}

impl<T> ImportResolver for AsWasmiVM<T>
where
    T: IsWasmiVM<T>,
{
    fn resolve_func(
        &self,
        module_name: &str,
        field_name: &str,
        signature: &wasmi::Signature,
    ) -> Result<wasmi::FuncRef, wasmi::Error> {
        let module = self
            .0
            .host_functions_definitions()
            .get(&WasmiModuleName(module_name.to_owned()))
            .ok_or(wasmi::Error::Instantiation(format!(
                "A module tried to load an unknown host module: {}",
                module_name
            )))?;
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

#[derive(PartialEq, Eq, Debug)]
pub enum WasmiModuleError {
    WasmiError(wasmi::Error),
    MemoryWriteError(MemoryWriteError),
    MemoryReadError(MemoryReadError),
    WasmiMemoryWriteFailure,
    WasmiMemoryReadFailure,
    NoRuntimeValueReturned,
}
impl From<wasmi::Error> for WasmiModuleError {
    fn from(e: wasmi::Error) -> Self {
        WasmiModuleError::WasmiError(e)
    }
}
impl From<MemoryWriteError> for WasmiModuleError {
    fn from(e: MemoryWriteError) -> Self {
        WasmiModuleError::MemoryWriteError(e)
    }
}
impl From<MemoryReadError> for WasmiModuleError {
    fn from(e: MemoryReadError) -> Self {
        WasmiModuleError::MemoryReadError(e)
    }
}

pub struct WasmiModuleOutput<'a>(
    Either<&'a wasmi::MemoryRef, (&'a wasmi::MemoryRef, RuntimeValue)>,
);
impl<'a> Pointable for WasmiModuleOutput<'a> {
    type Pointer = u32;
}

pub struct WasmiModuleInput<'a>(WasmiFunctionName, WasmiFunctionArgs<'a>);

pub struct WasmiModule<T> {
    module: wasmi::ModuleRef,
    memory: wasmi::MemoryRef,
    _marker: PhantomData<T>,
}

impl Pointable for wasmi::MemoryRef {
    type Pointer = u32;
}

impl ReadableMemory for wasmi::MemoryRef {
    type Error = WasmiModuleError;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.get_into(offset, buffer)
            .map_err(|_| WasmiModuleError::WasmiMemoryReadFailure)
    }
}

impl WritableMemory for wasmi::MemoryRef {
    type Error = WasmiModuleError;
    fn write(&self, offset: Self::Pointer, buffer: &[u8]) -> Result<(), Self::Error> {
        self.set(offset, buffer)
            .map_err(|_| WasmiModuleError::WasmiMemoryWriteFailure)
    }
}

impl ReadWriteMemory for wasmi::MemoryRef {}

impl<T> Module for WasmiModule<T>
where
    T: 'static + Externals,
{
    type Id = WasmiModuleId;
    type Input<'a> = WasmiModuleInput<'a>;
    type Output<'a> = WasmiModuleOutput<'a>;
    type VM = T;
    type Memory = wasmi::MemoryRef;
    type Error = WasmiModuleError;
    fn memory(&self) -> &Self::Memory {
        &self.memory
    }
    fn call<'a, O, E>(
        &self,
        runtime: &mut Self::VM,
        WasmiModuleInput(WasmiFunctionName(function_name), (function_args, _)): Self::Input<'a>,
    ) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::Output<'x>, Error = E>,
        Self::Error: From<E>,
    {
        let value = self
            .module
            .invoke_export(&function_name, &function_args, runtime)?;
        Ok(O::try_from(WasmiModuleOutput(match value {
            Some(non_unit) => Either::Right((&self.memory, non_unit)),
            None => Either::Left(&self.memory),
        }))?)
    }
}

impl<T> VM for AsWasmiVM<T>
where
    T: 'static + IsWasmiVM<T>,
{
    type Module = WasmiModule<Self>;
    type Error = WasmiVMError;
    fn load(
        &mut self,
        module_id: &<Self::Module as Module>::Id,
    ) -> Result<Self::Module, Self::Error> {
        let module_code = self
            .0
            .codes()
            .get(module_id)
            .ok_or(WasmiVMError::ModuleNotFound)?;
        let wasmi_module = wasmi::Module::from_buffer(&module_code)?;
        let not_started_module_instance = wasmi::ModuleInstance::new(&wasmi_module, self)?;
        let module_instance = not_started_module_instance.run_start(&mut NopExternals)?;
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
            _marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        executor::{AllocateInput, AsSimpleExecutor, CosmwasmQueryInput},
        tagged::Tagged,
    };
    use alloc::vec;
    use cosmwasm_minimal_std::{Addr, BlockInfo, ContractInfo, Env, Timestamp};

    impl<'a> TryFrom<WasmiModuleOutput<'a>> for RuntimeValue {
        type Error = WasmiModuleError;
        fn try_from(WasmiModuleOutput(value): WasmiModuleOutput<'a>) -> Result<Self, Self::Error> {
            match value {
                Either::Left(_) => Err(WasmiModuleError::NoRuntimeValueReturned),
                Either::Right((_, rt_value)) => Ok(rt_value),
            }
        }
    }

    impl<'a> TryFrom<WasmiModuleOutput<'a>> for u32 {
        type Error = WasmiModuleError;
        fn try_from(WasmiModuleOutput(value): WasmiModuleOutput<'a>) -> Result<Self, Self::Error> {
            match value {
                Either::Right((_, RuntimeValue::I32(rt_value))) => Ok(rt_value as u32),
                _ => Err(WasmiModuleError::NoRuntimeValueReturned),
            }
        }
    }

    impl<'a> TryFrom<AllocateInput<u32>> for WasmiModuleInput<'a> {
        type Error = WasmiVMError;
        fn try_from(AllocateInput(ptr): AllocateInput<u32>) -> Result<Self, Self::Error> {
            Ok(WasmiModuleInput(
                WasmiFunctionName("allocate".to_owned()),
                (vec![RuntimeValue::I32(ptr as i32)], PhantomData),
            ))
        }
    }

    impl<'a> TryFrom<CosmwasmQueryInput<'a, u32>> for WasmiModuleInput<'a> {
        type Error = WasmiVMError;
        fn try_from(
            CosmwasmQueryInput(Tagged(env_ptr, _), Tagged(msg_ptr, _)): CosmwasmQueryInput<'a, u32>,
        ) -> Result<Self, Self::Error> {
            Ok(WasmiModuleInput(
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

    struct SimpleWasmiVM {
        codes: BTreeMap<WasmiModuleId, Vec<u8>>,
        host_functions_definitions: BTreeMap<WasmiModuleName, WasmiHostModule<Self>>,
        host_functions: BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<Self>>,
    }

    impl IsWasmiVM<SimpleWasmiVM> for SimpleWasmiVM {
        fn codes(&self) -> &BTreeMap<WasmiModuleId, Vec<u8>> {
            &self.codes
        }

        fn host_functions_definitions(
            &self,
        ) -> &BTreeMap<WasmiModuleName, WasmiHostModule<SimpleWasmiVM>> {
            &self.host_functions_definitions
        }

        fn host_functions(
            &self,
        ) -> &BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<SimpleWasmiVM>> {
            &self.host_functions
        }
    }

    fn env_db_read(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_read");
        Ok(None)
    }

    fn env_db_write(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_write");
        Ok(None)
    }

    fn env_db_remove(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_remove");
        Ok(None)
    }

    fn env_db_scan(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_scan");
        Ok(None)
    }

    fn env_db_next(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_next");
        Ok(None)
    }

    fn env_addr_validate(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("addr_validate");
        Ok(None)
    }

    fn env_addr_canonicalize(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("addr_canonicalize");
        Ok(None)
    }

    fn env_addr_humanize(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("addr_humanize");
        Ok(None)
    }

    fn env_secp256k1_verify(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("secp256k1_verify");
        Ok(None)
    }

    fn env_secp256k1_batch_verify(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("secp256k1_batch_verify");
        Ok(None)
    }

    fn env_secp256k1_recove_pubkey(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("secp256k1_recove_pubkey");
        Ok(None)
    }

    fn env_ed25519_verify(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("ed25519_verify");
        Ok(None)
    }

    fn env_ed25519_batch_verify(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("ed25519_batch_verify");
        Ok(None)
    }

    fn env_debug(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("debug");
        Ok(None)
    }

    fn env_query_chain(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("query_chain");
        Ok(None)
    }

    #[test]
    fn test() {
        env_logger::builder().init();
        let code = include_bytes!("../../fixtures/cw20_base.wasm").to_vec();
        // module -> function -> (index, ptr)
        let host_functions_definitions = BTreeMap::from([(
            WasmiModuleName("env".to_owned()),
            BTreeMap::from([
                (
                    WasmiFunctionName("db_read".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0001),
                        env_db_read as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("db_write".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0002),
                        env_db_write as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("db_remove".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0003),
                        env_db_remove as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("db_scan".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0004),
                        env_db_scan as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("db_next".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0005),
                        env_db_next as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_validate".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0006),
                        env_addr_validate as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_canonicalize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0007),
                        env_addr_canonicalize as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_humanize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0008),
                        env_addr_humanize as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0009),
                        env_secp256k1_verify as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000A),
                        env_secp256k1_batch_verify as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_recover_pubkey".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000B),
                        env_secp256k1_recove_pubkey as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000C),
                        env_ed25519_verify as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000D),
                        env_ed25519_batch_verify as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("debug".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000E),
                        env_debug as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("query_chain".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000F),
                        env_query_chain as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
            ]),
        )]);
        let mut vm = AsWasmiVM(SimpleWasmiVM {
            codes: BTreeMap::from([(WasmiModuleId(0xDEADC0DE), code)]),
            host_functions_definitions: host_functions_definitions.clone(),
            host_functions: host_functions_definitions
                .into_iter()
                .map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
                .flatten()
                .collect(),
        });
        let mut executor = AsSimpleExecutor { vm };
        let module = executor.vm.load(&WasmiModuleId(0xDEADC0DE)).unwrap();
        executor
            .cosmwasm_query(
                &module,
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
            .unwrap();
    }
}
