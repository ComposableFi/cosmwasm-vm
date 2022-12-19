use alloc::{string::String, vec, vec::Vec};
use core::mem;
use cosmwasm_std::{ContractResult, Empty, Response};
use cosmwasm_vm::executor::{
    AllocateCall, AsFunctionName, DeallocateCall, ExecuteCall, InstantiateCall, MigrateCall,
    QueryCall, ReplyCall,
};
use serde::Serialize;
use wasm_instrument::parity_wasm::{
    builder,
    elements::{FuncBody, Instruction, Instructions, Local, ValueType},
};

pub const INDEX_OF_USER_DEFINED_FNS: u32 = 9;
const INDEX_OF_LAST_UNRESERVED_MEMORY_CURSOR: u32 = 0;
// We know this won't truncate as it is being executed in a 32-bit wasm context
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
const SIZE_OF_I32: i32 = mem::size_of::<i32>() as i32;
/// Size of `CosmWasm` `Region`
/// `offset` + `capacity` + `length`
/// <https://github.com/CosmWasm/cosmwasm/blob/0ba91a53488f1a00fd1fa702c0055bfa324d395a/README.md?plain=1#L271>
const SIZE_OF_REGION: i32 = SIZE_OF_I32 * 3;

pub struct InterfaceVersion8Call;

impl AsFunctionName for InterfaceVersion8Call {
    const NAME: &'static str = "interface_version_8";
}

pub struct DummyCall;

impl AsFunctionName for DummyCall {
    const NAME: &'static str = "dummy_fn";
}

/// Definition for the wasm code
#[derive(Debug)]
pub struct ModuleDefinition {
    instantiate_call: InstantiateFn,
    execute_call: ExecuteFn,
    migrate_call: MigrateFn,
    query_call: QueryFn,
    reply_call: ReplyFn,
    table: Option<Table>,
    additional_functions: Vec<Function>,
    additional_binary_size: usize,
}

/// A wasm module ready to be put on chain.
#[derive(Clone)]
pub struct WasmModule {
    pub code: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    Internal,
}

#[derive(Debug)]
pub struct Table(Vec<u32>);

impl Table {
    #[must_use]
    pub fn new(table: Vec<u32>) -> Self {
        Self(table)
    }

    #[must_use]
    pub fn fill(function_index: u32, n_elems: usize) -> Self {
        Self(vec![function_index; n_elems])
    }
}

impl ModuleDefinition {
    pub fn new(
        additional_functions: Vec<Function>,
        additional_binary_size: usize,
        table: Option<Table>,
    ) -> Result<Self, Error> {
        Ok(Self {
            instantiate_call: InstantiateFn::new().map_err(|_| Error::Internal)?,
            execute_call: ExecuteFn::new().map_err(|_| Error::Internal)?,
            migrate_call: MigrateFn::new().map_err(|_| Error::Internal)?,
            query_call: QueryFn::new().map_err(|_| Error::Internal)?,
            reply_call: ReplyFn::new().map_err(|_| Error::Internal)?,
            table,
            additional_functions,
            additional_binary_size,
        })
    }

    pub fn with_instructions<F: Into<String>>(
        fn_name: F,
        mut instructions: Vec<Instruction>,
        additional_binary_size: usize,
        table: Option<Table>,
    ) -> Result<Self, Error> {
        instructions.push(Instruction::End);
        Self::new(
            vec![Function {
                name: fn_name.into(),
                params: Vec::new(),
                result: None,
                definition: FuncBody::new(Vec::new(), Instructions::new(instructions)),
            }],
            additional_binary_size,
            table,
        )
    }

    pub fn with_instantiate_response<S: Serialize>(response: S) -> Result<Self, Error> {
        Ok(Self {
            instantiate_call: InstantiateFn(
                InstantiateFn::plain(response).map_err(|_| Error::Internal)?,
            ),
            execute_call: ExecuteFn::new().map_err(|_| Error::Internal)?,
            migrate_call: MigrateFn::new().map_err(|_| Error::Internal)?,
            query_call: QueryFn::new().map_err(|_| Error::Internal)?,
            reply_call: ReplyFn::new().map_err(|_| Error::Internal)?,
            table: None,
            additional_functions: Vec::new(),
            additional_binary_size: 0,
        })
    }
}

#[derive(Debug)]
pub struct Function {
    pub name: String,
    pub params: Vec<ValueType>,
    pub result: Option<ValueType>,
    pub definition: FuncBody,
}

impl Function {
    #[must_use]
    pub fn instructions(&self) -> &Instructions {
        self.definition.code()
    }
}

pub struct FunctionBuilder(Function);

impl FunctionBuilder {
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self(Function {
            name: name.into(),
            params: Vec::new(),
            result: None,
            definition: FuncBody::empty(),
        })
    }

    #[must_use]
    pub fn param(mut self, param: ValueType) -> Self {
        self.0.params.push(param);
        self
    }

    #[must_use]
    pub fn result(mut self, result: ValueType) -> Self {
        self.0.result = Some(result);
        self
    }

    #[must_use]
    pub fn definition(mut self, func_body: FuncBody) -> Self {
        self.0.definition = func_body;
        self
    }

    #[must_use]
    pub fn build(self) -> Function {
        self.0
    }

    #[must_use]
    pub fn local(mut self, count: u32, value_type: ValueType) -> Self {
        self.0
            .definition
            .locals_mut()
            .push(Local::new(count, value_type));
        self
    }

    #[must_use]
    pub fn instructions(mut self, instructions: Vec<Instruction>) -> Self {
        *self.0.definition.code_mut() = Instructions::new(instructions);
        self
    }
}

trait EntrypointCall {
    const MSG_PTR_INDEX: u32;
    /// Plain entrypoint which just returns the response as is
    /// `msg_ptr_index` is the index of the `msg_ptr` parameter in cosmwasm api
    /// this index is 2 in `query` but 3 in `execute`
    fn plain<T: serde::Serialize>(response: T) -> Result<FuncBody, serde_json::Error> {
        let result = serde_json::to_string(&response)?;

        let instructions = vec![
            vec![
                // Allocate space for the response
                // we target wasm32 so this will not truncate
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                Instruction::I32Const(result.len() as i32),
                Instruction::Call(0),
                // we save the ptr
                Instruction::SetLocal(Self::MSG_PTR_INDEX + 1),
                Instruction::GetLocal(Self::MSG_PTR_INDEX + 1),
                // now we should set the length to response.len()
                Instruction::I32Const(8),
                Instruction::I32Add,
                // we target wasm32 so this will not truncate
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                Instruction::I32Const(result.len() as i32),
                Instruction::I32Store(0, 0),
                Instruction::GetLocal(Self::MSG_PTR_INDEX + 1),
                // returned ptr to { offset: i32, capacity: i32, length: i32 }
                Instruction::I32Load(0, 0),
                // now we load offset and save it to local_var_3
                Instruction::SetLocal(Self::MSG_PTR_INDEX),
                Instruction::GetLocal(Self::MSG_PTR_INDEX),
            ],
            {
                let mut instructions = Vec::new();
                for c in result.chars() {
                    instructions.extend(vec![
                        Instruction::GetLocal(Self::MSG_PTR_INDEX),
                        Instruction::I32Const(c as i32),
                        Instruction::I32Store(0, 0),
                        Instruction::GetLocal(Self::MSG_PTR_INDEX),
                        Instruction::I32Const(1),
                        Instruction::I32Add,
                        Instruction::SetLocal(Self::MSG_PTR_INDEX),
                    ]);
                }
                instructions
            },
            vec![
                Instruction::GetLocal(Self::MSG_PTR_INDEX + 1),
                Instruction::Return,
                Instruction::End,
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<Instruction>>();

        Ok(FuncBody::new(
            vec![Local::new(2, ValueType::I32)],
            Instructions::new(instructions),
        ))
    }
}

#[derive(Debug)]
struct ExecuteFn(FuncBody);

impl EntrypointCall for ExecuteFn {
    const MSG_PTR_INDEX: u32 = 3;
}

impl ExecuteFn {
    pub fn new() -> Result<Self, serde_json::Error> {
        let response = Response::<Empty>::default();
        Ok(ExecuteFn(Self::plain(ContractResult::Ok(response))?))
    }
}

#[derive(Debug)]
struct InstantiateFn(FuncBody);

impl EntrypointCall for InstantiateFn {
    const MSG_PTR_INDEX: u32 = 3;
}

impl InstantiateFn {
    pub fn new() -> Result<Self, serde_json::Error> {
        let response = Response::<Empty>::default();
        Ok(InstantiateFn(Self::plain(ContractResult::Ok(response))?))
    }
}

#[derive(Debug)]
struct MigrateFn(FuncBody);

impl EntrypointCall for MigrateFn {
    const MSG_PTR_INDEX: u32 = 2;
}

impl MigrateFn {
    pub fn new() -> Result<Self, serde_json::Error> {
        let response = Response::<Empty>::default();
        Ok(MigrateFn(Self::plain(ContractResult::Ok(response))?))
    }
}

#[derive(Debug)]
struct QueryFn(FuncBody);

impl EntrypointCall for QueryFn {
    const MSG_PTR_INDEX: u32 = 2;
}

impl QueryFn {
    pub fn new() -> Result<Self, serde_json::Error> {
        let encoded_result = hex::encode("{}");
        Ok(QueryFn(Self::plain(ContractResult::Ok(encoded_result))?))
    }
}

#[derive(Debug)]
struct ReplyFn(FuncBody);

impl EntrypointCall for ReplyFn {
    const MSG_PTR_INDEX: u32 = 2;
}

impl ReplyFn {
    pub fn new() -> Result<Self, serde_json::Error> {
        let response = Response::<Empty>::default();
        Ok(ReplyFn(Self::plain(ContractResult::Ok(response))?))
    }
}

impl From<ModuleDefinition> for WasmModule {
    #[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
    fn from(def: ModuleDefinition) -> Self {
        let mut contract = builder::module()
            // Generate memory
            .memory()
            .build()
            // Add a global variable to be used in allocate function
            .global()
            .with_type(ValueType::I32)
            .mutable()
            .init_expr(Instruction::I32Const(0))
            .build()
            // Export memory
            .export()
            .field("memory")
            .internal()
            .memory(0)
            .build();

        // This is for indirect call table, we only support a single table
        if let Some(table) = def.table {
            contract = contract
                .table()
                .with_min(table.0.len() as u32)
                .with_max(Some(table.0.len() as u32))
                .with_element(0, table.0)
                .build();
        }

        let mut function_definitions = vec![
            // fn allocate(size: usize) -> u32;
            Function {
                name: AllocateCall::<()>::NAME.into(),
                params: vec![ValueType::I32], // how much memory to allocate
                result: Some(ValueType::I32), // ptr to the region of the new memory
                definition: FuncBody::new(
                    Vec::new(), // We don't need any local variables
                    Instructions::new(vec![
                        // Save original memory cursor in order to return it at the end
                        // Once we have allocated the memory for the new region
                        Instruction::GetGlobal(INDEX_OF_LAST_UNRESERVED_MEMORY_CURSOR),
                        // reserve space
                        // save offset as global offset ptr + 12
                        Instruction::GetGlobal(INDEX_OF_LAST_UNRESERVED_MEMORY_CURSOR),
                        Instruction::I32Const(SIZE_OF_REGION),
                        Instruction::GetGlobal(INDEX_OF_LAST_UNRESERVED_MEMORY_CURSOR),
                        Instruction::I32Add,
                        Instruction::I32Store(0, 0),
                        // set capacity to input reserve size
                        Instruction::GetGlobal(INDEX_OF_LAST_UNRESERVED_MEMORY_CURSOR),
                        Instruction::I32Const(SIZE_OF_I32),
                        Instruction::I32Add,
                        Instruction::GetLocal(0),
                        Instruction::I32Store(0, 0),
                        // set length to 0
                        Instruction::GetGlobal(INDEX_OF_LAST_UNRESERVED_MEMORY_CURSOR),
                        Instruction::I32Const(SIZE_OF_I32 * 2),
                        Instruction::I32Add,
                        Instruction::I32Const(0),
                        Instruction::I32Store(0, 0),
                        // increase global offset ptr by (12 + capacity)
                        Instruction::GetGlobal(INDEX_OF_LAST_UNRESERVED_MEMORY_CURSOR),
                        Instruction::I32Const(SIZE_OF_REGION),
                        Instruction::I32Add,
                        Instruction::GetLocal(0),
                        Instruction::I32Add,
                        // increase global offset ptr by allocated size
                        Instruction::SetGlobal(INDEX_OF_LAST_UNRESERVED_MEMORY_CURSOR),
                        // Return the original memory cursor which we have cached at the
                        // beginning of this function
                        Instruction::Return,
                        Instruction::End,
                    ]),
                ),
            },
            // fn instantiate(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32;
            Function {
                name: <InstantiateCall>::NAME.into(),
                params: vec![ValueType::I32, ValueType::I32, ValueType::I32],
                result: Some(ValueType::I32),
                definition: def.instantiate_call.0,
            },
            // fn execute(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32;
            Function {
                name: <ExecuteCall>::NAME.into(),
                params: vec![ValueType::I32, ValueType::I32, ValueType::I32],
                result: Some(ValueType::I32),
                definition: def.execute_call.0,
            },
            // fn migrate(env_ptr: u32, msg_ptr: u32) -> u32;
            Function {
                name: <MigrateCall>::NAME.into(),
                params: vec![ValueType::I32, ValueType::I32],
                result: Some(ValueType::I32),
                definition: def.migrate_call.0,
            },
            // fn deallocate(pointer: u32);
            // NOTE: We are not deallocating memory because for our usecase it does
            // not affect performance.
            Function {
                name: DeallocateCall::<()>::NAME.into(),
                params: vec![ValueType::I32],
                result: None,
                definition: FuncBody::new(Vec::new(), Instructions::empty()),
            },
            // fn query(env_ptr: u32, msg_ptr: u32) -> u32;
            Function {
                name: QueryCall::NAME.into(),
                params: vec![ValueType::I32, ValueType::I32],
                result: Some(ValueType::I32),
                definition: def.query_call.0,
            },
            // fn reply(env_ptr: u32, msg_ptr: u32) -> u32;
            Function {
                name: <ReplyCall>::NAME.into(),
                params: vec![ValueType::I32, ValueType::I32],
                result: Some(ValueType::I32),
                definition: def.reply_call.0,
            },
            // dummy function to increase the binary size
            // Used for increasing the total wasm's size.
            // Useful when benchmarking for different binary sizes.
            Function {
                name: DummyCall::NAME.into(),
                params: vec![],
                result: None,
                definition: FuncBody::new(
                    Vec::new(),
                    Instructions::new({
                        let mut nops = vec![Instruction::Nop; def.additional_binary_size];
                        nops.push(Instruction::End);
                        nops
                    }),
                ),
            },
            // fn interface_version_8() -> ();
            // Required in order to signal compatibility with CosmWasm 1.0
            // <https://github.com/CosmWasm/cosmwasm/blob/0ba91a53488f1a00fd1fa702c0055bfa324d395a/README.md?plain=1#L153>
            Function {
                name: InterfaceVersion8Call::NAME.into(),
                params: vec![],
                result: None,
                definition: FuncBody::new(Vec::new(), Instructions::empty()),
            },
        ];

        // Add functions definied by users.
        // Useful for benchmarking
        for function in def.additional_functions {
            function_definitions.push(function);
        }

        // we target wasm32 so this will not truncate
        #[allow(clippy::cast_possible_wrap)]
        for (i, func) in function_definitions.into_iter().enumerate() {
            let mut signature_builder = contract.function().signature();
            if !func.params.is_empty() {
                signature_builder = signature_builder.with_params(func.params);
            }
            if let Some(result) = func.result {
                signature_builder = signature_builder.with_result(result);
            }

            contract = signature_builder
                .build()
                .with_body(func.definition)
                .build()
                .export()
                .field(func.name.as_str())
                .internal()
                .func(i as u32)
                .build();
        }

        let code = contract.build().into_bytes().unwrap();
        Self { code }
    }
}
