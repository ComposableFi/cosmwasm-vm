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
use crate::memory::MemoryReadError;
use crate::memory::MemoryWriteError;
use crate::memory::Pointable;
use crate::memory::ReadWriteMemory;
use crate::memory::ReadableMemory;
use crate::memory::WritableMemory;
use crate::tagged::Tagged;
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

pub trait IsWasmiVM<T>: for<'x> From<(Self::Resolver<'x>, WasmiModule)> {
    type Resolver<'a>: ImportResolver;
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

pub struct WasmiImportResolver<'a, T>(&'a BTreeMap<WasmiModuleName, WasmiHostModule<T>>);
impl<'a, T> ImportResolver for WasmiImportResolver<'a, T> {
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

impl<T> VM for AsWasmiVM<T>
where
    T: 'static + IsWasmiVM<T>,
{
    type Input<'a> = WasmiInput<'a>;
    type Output<'a> = WasmiOutput<'a>;
    type Error = WasmiVMError;
    type Code<'a> = (T::Resolver<'a>, &'a [u8]);
    fn load<'a>((import_resolver, code): Self::Code<'a>) -> Result<Self, Self::Error> {
        let wasmi_module = wasmi::Module::from_buffer(code)?;
        let not_started_module_instance =
            wasmi::ModuleInstance::new(&wasmi_module, &import_resolver)?;
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
                import_resolver,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{constants, ConstantReadLimit, InstantiateInput};
    use core::assert_matches::assert_matches;
    use cosmwasm_minimal_std::{
        Addr, Binary, BlockInfo, ContractInfo, CosmwasmExecutionResult, CosmwasmQueryResult, Env,
        InstantiateResult, MessageInfo, QueryResult, Timestamp,
    };

    struct SimpleWasmiVM {
        host_functions_definitions: BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<Self>>>,
        host_functions: BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<AsWasmiVM<Self>>>,
        storage: BTreeMap<Vec<u8>, Vec<u8>>,
        executing_module: WasmiModule,
    }

    impl<'a>
        From<(
            WasmiImportResolver<'a, AsWasmiVM<SimpleWasmiVM>>,
            WasmiModule,
        )> for SimpleWasmiVM
    {
        fn from(
            (WasmiImportResolver(host_functions_definitions), executing_module): (
                WasmiImportResolver<'a, AsWasmiVM<SimpleWasmiVM>>,
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
                storage: Default::default(),
                executing_module,
            }
        }
    }

    impl IsWasmiVM<SimpleWasmiVM> for SimpleWasmiVM {
        type Resolver<'a> = WasmiImportResolver<'a, AsWasmiVM<Self>>;

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

    fn env_db_read(
        vm: &mut AsWasmiVM<SimpleWasmiVM>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_read");
        match &values[..] {
            [RuntimeValue::I32(key_pointer)] => {
                let key = vm
                    .passthrough_out::<ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>>(
                        *key_pointer as u32,
                    )?;
                let value =
                    vm.0.storage
                        .get(&key)
                        .ok_or(WasmiVMError::StorageKeyNotFound(key))?
                        .clone();
                let Tagged(value_pointer, _) = vm.passthrough_in::<()>(&value)?;
                Ok(Some(RuntimeValue::I32(value_pointer as i32)))
            }
            _ => Err(WasmiVMError::InvalidHostSignature),
        }
    }

    fn env_db_write(
        vm: &mut AsWasmiVM<SimpleWasmiVM>,
        values: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
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
                vm.0.storage.insert(key, value);
                Ok(None)
            }
            _ => Err(WasmiVMError::InvalidHostSignature),
        }
    }

    fn env_db_remove(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_remove");
        Ok(None)
    }

    fn env_db_scan(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_scan");
        Ok(None)
    }

    fn env_db_next(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("db_next");
        Ok(None)
    }

    fn env_addr_validate(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("addr_validate");
        Ok(None)
    }

    fn env_addr_canonicalize(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("addr_canonicalize");
        Ok(None)
    }

    fn env_addr_humanize(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("addr_humanize");
        Ok(None)
    }

    fn env_secp256k1_verify(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("secp256k1_verify");
        Ok(None)
    }

    fn env_secp256k1_batch_verify(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("secp256k1_batch_verify");
        Ok(None)
    }

    fn env_secp256k1_recove_pubkey(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("secp256k1_recove_pubkey");
        Ok(None)
    }

    fn env_ed25519_verify(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("ed25519_verify");
        Ok(None)
    }

    fn env_ed25519_batch_verify(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("ed25519_batch_verify");
        Ok(None)
    }

    fn env_debug(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        log::debug!("debug");
        Ok(None)
    }

    fn env_query_chain(
        _: &mut AsWasmiVM<SimpleWasmiVM>,
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
                        env_db_read as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_write".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0002),
                        env_db_write as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_remove".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0003),
                        env_db_remove as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_scan".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0004),
                        env_db_scan as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("db_next".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0005),
                        env_db_next as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_validate".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0006),
                        env_addr_validate as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_canonicalize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0007),
                        env_addr_canonicalize as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("addr_humanize".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0008),
                        env_addr_humanize as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0009),
                        env_secp256k1_verify as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000A),
                        env_secp256k1_batch_verify as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("secp256k1_recover_pubkey".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000B),
                        env_secp256k1_recove_pubkey as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000C),
                        env_ed25519_verify as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("ed25519_batch_verify".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000D),
                        env_ed25519_batch_verify as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("debug".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000E),
                        env_debug as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
                (
                    WasmiFunctionName("query_chain".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x000F),
                        env_query_chain as WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>>,
                    ),
                ),
            ]),
        )]);
        let mut vm = <AsWasmiVM<SimpleWasmiVM>>::load((
            WasmiImportResolver(&host_functions_definitions),
            &code,
        ))
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
    }
}
