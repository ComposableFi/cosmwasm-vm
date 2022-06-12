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

use crate::vm::*;
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::fmt::Display;
use either::Either;
use wasmi::Externals;
use wasmi::FuncInstance;
use wasmi::HostError;
use wasmi::ImportResolver;
use wasmi::MemoryRef;
use wasmi::ModuleRef;
use wasmi::NopExternals;
use wasmi::RuntimeValue;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WasmiFunctionName(String);
pub type WasmiFunctionArgs<'a> = &'a [RuntimeValue];
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WasmiModuleName(String);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WasmiHostFunctionIndex(usize);
pub type WasmiHostFunction<T> =
    fn(&mut T, &[RuntimeValue]) -> Result<Option<RuntimeValue>, WasmiVMError>;
pub type WasmiHostModule<T> =
    BTreeMap<WasmiFunctionName, (WasmiHostFunctionIndex, WasmiHostFunction<T>)>;

#[derive(Debug)]
pub struct WasmiModule {
    inner_module: ModuleRef,
    memory: MemoryRef,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WasmiModuleId(u32);
#[derive(PartialEq, Eq, Debug)]
pub enum WasmiVMError {
    WasmiError(wasmi::Error),
    WasmiTrap(wasmi::Trap),
    ModuleNotFound,
    MemoryNotExported,
    MemoryExportedIsNotMemory,
    HostFunctionNotFound(WasmiHostFunctionIndex),
    HostFunctionFailure(String),
}
impl From<wasmi::Error> for WasmiVMError {
    fn from(e: wasmi::Error) -> Self {
        WasmiVMError::WasmiError(e)
    }
}
impl From<wasmi::Trap> for WasmiVMError {
    fn from(e: wasmi::Trap) -> Self {
        WasmiVMError::WasmiTrap(e)
    }
}
impl Display for WasmiVMError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl HostError for WasmiVMError {}

pub struct AsWasmiVM<T>(T);

pub trait IsWasmiVM<T> {
    fn codes(&self) -> &BTreeMap<WasmiModuleId, Vec<u8>>;
    fn host_functions_definitions(&self) -> &BTreeMap<WasmiModuleName, WasmiHostModule<T>>;
    fn host_functions(&self) -> &BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<T>>;
}

impl<T: IsWasmiVM<T>> Externals for AsWasmiVM<T> {
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

impl<T: IsWasmiVM<T>> ImportResolver for AsWasmiVM<T> {
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
    ) -> Result<MemoryRef, wasmi::Error> {
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

impl<T: IsWasmiVM<T>> VM for AsWasmiVM<T> {
    type FunctionName = WasmiFunctionName;
    type FunctionArgs<'a> = WasmiFunctionArgs<'a>;
    type RawOutput<'a> = Either<&'a MemoryRef, (&'a MemoryRef, RuntimeValue)>;
    type ModuleId = WasmiModuleId;
    type Error = WasmiVMError;

    fn raw_call<'a: 'b, 'b, O, E>(
        &'a mut self,
        module_id: &Self::ModuleId,
        WasmiFunctionName(function_name): Self::FunctionName,
        function_args: Self::FunctionArgs<'b>,
    ) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::RawOutput<'x>, Error = E>,
        Self::Error: From<E>,
    {
        let module_code = self
            .0
            .codes()
            .get(module_id)
            .ok_or(WasmiVMError::ModuleNotFound)?;
        let wasmi_module = wasmi::Module::from_buffer(&module_code)?;
        let not_started_instance = wasmi::ModuleInstance::new(&wasmi_module, self)?;
        let instance = not_started_instance.run_start(&mut NopExternals)?;
        let memory_exported = instance
            .export_by_name("memory")
            .ok_or(WasmiVMError::MemoryNotExported)?;
        let memory = match memory_exported {
            wasmi::ExternVal::Memory(mem) => Ok(mem),
            _ => Err(WasmiVMError::MemoryExportedIsNotMemory),
        }?;
        let loaded_module = WasmiModule {
            inner_module: instance,
            memory,
        };
        let value =
            loaded_module
                .inner_module
                .invoke_export(&function_name, function_args, self)?;
        Ok(O::try_from(match value {
            Some(non_unit) => Either::Right((&loaded_module.memory, non_unit)),
            None => Either::Left(&loaded_module.memory),
        })?)
    }
}

#[derive(Debug)]
struct DummyInput<'a>(String, &'a [RuntimeValue]);
impl<'a> From<DummyInput<'a>> for (WasmiFunctionName, &'a [RuntimeValue]) {
    fn from(DummyInput(function_name, args): DummyInput<'a>) -> Self {
        (WasmiFunctionName(function_name), args)
    }
}

#[derive(PartialEq, Eq, Debug)]
struct DummyOutput;
impl TryFrom<Either<&MemoryRef, (&MemoryRef, RuntimeValue)>> for DummyOutput {
    type Error = WasmiVMError;
    fn try_from(_: Either<&MemoryRef, (&MemoryRef, RuntimeValue)>) -> Result<Self, Self::Error> {
        Ok(DummyOutput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    struct SimpleWasmiVM {
        codes: BTreeMap<WasmiModuleId, Vec<u8>>,
        host_functions_definitions: BTreeMap<WasmiModuleName, WasmiHostModule<Self>>,
        host_functions: BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<Self>>,
        counter: u32,
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

    const NOT_IMPLEMENTED: &'static str = "NOT_IMPLEMENTED_MAGICC0DE";
    fn env_assert(
        _: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        Err(WasmiVMError::HostFunctionFailure(
            NOT_IMPLEMENTED.to_owned(),
        ))
    }

    fn env_increment(
        vm: &mut SimpleWasmiVM,
        _: &[RuntimeValue],
    ) -> Result<Option<RuntimeValue>, WasmiVMError> {
        vm.counter += 1;
        Ok(None)
    }

    #[test]
    fn test() {
        let wat = r#"
            (module
                (import "env" "assert" (func $assert (param i32)))
                (import "env" "increment" (func $increment))
                (memory (export "memory") 2 3)
                (func (export "increment")
                  (call $increment))
			          (func (export "call") (param $x i32) (param $y i64)
				          ;; assert that $x = 0x12345678
				          (call $assert
					          (i32.eq
						          (get_local $x)
						          (i32.const 0x12345678)
					          )
				          )
				          (call $assert
					          (i64.eq
						          (get_local $y)
						          (i64.const 0x1234567887654321)
					          )
				          )
			          )
            )
        "#;
        let code = wat::parse_str(wat).unwrap();
        // module -> function -> (index, ptr)
        let host_functions_definitions = BTreeMap::from([(
            WasmiModuleName("env".to_owned()),
            BTreeMap::from([
                (
                    WasmiFunctionName("assert".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0001),
                        env_assert as WasmiHostFunction<SimpleWasmiVM>,
                    ),
                ),
                (
                    WasmiFunctionName("increment".to_owned()),
                    (
                        WasmiHostFunctionIndex(0x0002),
                        env_increment as WasmiHostFunction<SimpleWasmiVM>,
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
            counter: 0,
        });
        assert_eq!(
            vm.call::<DummyInput, DummyOutput, _>(
                &WasmiModuleId(0),
                DummyInput("bar".to_owned(), &[]),
            ),
            Err(WasmiVMError::ModuleNotFound)
        );
        assert_eq!(
            vm.call::<DummyInput, DummyOutput, _>(
                &WasmiModuleId(0xDEADC0DE),
                DummyInput(
                    "call".to_owned(),
                    &[RuntimeValue::I32(0x1337), RuntimeValue::I64(0x3771)]
                ),
            ),
            Err(WasmiVMError::WasmiError(wasmi::Error::Trap(
                wasmi::Trap::Host(Box::new(WasmiVMError::HostFunctionFailure(
                    NOT_IMPLEMENTED.to_owned()
                )))
            )))
        );
        assert_eq!(vm.0.counter, 0);
        assert_eq!(
            vm.call::<DummyInput, DummyOutput, _>(
                &WasmiModuleId(0xDEADC0DE),
                DummyInput("increment".to_owned(), &[]),
            ),
            Ok(DummyOutput)
        );
        assert_eq!(vm.0.counter, 1);
    }
}
