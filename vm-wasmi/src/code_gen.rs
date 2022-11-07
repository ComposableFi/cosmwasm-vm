use alloc::string::String;
use alloc::{vec, vec::Vec};
use cosmwasm_minimal_std::{ContractResult, Empty, Response};
use wasm_instrument::parity_wasm::{
    builder,
    elements::{FuncBody, Instruction, Instructions, Local, ValueType},
};

/// Definition for the wasm code
#[derive(Debug)]
pub struct ModuleDefinition {
    instantiate_call: InstantiateCall,
    execute_call: ExecuteCall,
    migrate_call: MigrateCall,
    query_call: QueryCall,
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

impl ModuleDefinition {
    pub fn new(
        additional_functions: Vec<Function>,
        additional_binary_size: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            instantiate_call: InstantiateCall::new().map_err(|_| Error::Internal)?,
            execute_call: ExecuteCall::new().map_err(|_| Error::Internal)?,
            migrate_call: MigrateCall::new().map_err(|_| Error::Internal)?,
            query_call: QueryCall::new().map_err(|_| Error::Internal)?,
            additional_functions,
            additional_binary_size,
        })
    }

    pub fn with_instructions<F: Into<String>>(
        fn_name: F,
        mut instructions: Vec<Instruction>,
        additional_binary_size: usize,
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
        )
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

    pub fn param(mut self, param: ValueType) -> Self {
        self.0.params.push(param);
        self
    }

    pub fn result(mut self, result: ValueType) -> Self {
        self.0.result = Some(result);
        self
    }

    pub fn definition(mut self, func_body: FuncBody) -> Self {
        self.0.definition = func_body;
        self
    }

    pub fn build(self) -> Function {
        self.0
    }

    pub fn local(mut self, count: u32, value_type: ValueType) -> Self {
        self.0
            .definition
            .locals_mut()
            .push(Local::new(count, value_type));
        self
    }

    pub fn instructions(mut self, instructions: Vec<Instruction>) -> Self {
        *self.0.definition.code_mut() = Instructions::new(instructions);
        self
    }
}

trait EntrypointCall {
    /// Plain entrypoint which just returns the response as is
    /// `msg_ptr_index` is the index of the `msg_ptr` parameter in cosmwasm api
    /// this index is 2 in `query` but 3 in `execute`
    fn plain<T: serde::Serialize>(
        response: T,
        msg_ptr_index: u32,
    ) -> Result<FuncBody, serde_json::Error> {
        let result = serde_json::to_string(&response)?;

        let instructions = vec![
            vec![
                // Allocate space for the response
                Instruction::I32Const(result.len() as i32),
                Instruction::Call(0),
                // we save the ptr
                Instruction::SetLocal(msg_ptr_index + 1),
                Instruction::GetLocal(msg_ptr_index + 1),
                // now we should set the length to response.len()
                Instruction::I32Const(8),
                Instruction::I32Add,
                Instruction::I32Const(result.len() as i32),
                Instruction::I32Store(0, 0),
                Instruction::GetLocal(msg_ptr_index + 1),
                // returned ptr to { offset: i32, capacity: i32, length: i32 }
                Instruction::I32Load(0, 0),
                // now we load offset and save it to local_var_3
                Instruction::SetLocal(msg_ptr_index),
                Instruction::GetLocal(msg_ptr_index),
            ],
            {
                let mut instructions = Vec::new();
                for c in result.chars() {
                    instructions.extend(vec![
                        Instruction::GetLocal(msg_ptr_index),
                        Instruction::I32Const(c as i32),
                        Instruction::I32Store(0, 0),
                        Instruction::GetLocal(msg_ptr_index),
                        Instruction::I32Const(1),
                        Instruction::I32Add,
                        Instruction::SetLocal(msg_ptr_index),
                    ]);
                }
                instructions
            },
            vec![
                Instruction::GetLocal(msg_ptr_index + 1),
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
struct ExecuteCall(FuncBody);

impl EntrypointCall for ExecuteCall {}

impl ExecuteCall {
    pub fn new() -> Result<Self, serde_json::Error> {
        let response = Response::<Empty>::default();
        Ok(ExecuteCall(Self::plain(
            ContractResult::<Response<Empty>>::Ok(response),
            3,
        )?))
    }
}

#[derive(Debug)]
struct InstantiateCall(FuncBody);

impl EntrypointCall for InstantiateCall {}

impl InstantiateCall {
    pub fn new() -> Result<Self, serde_json::Error> {
        let response = Response::<Empty>::default();
        Ok(InstantiateCall(Self::plain(
            ContractResult::<Response<Empty>>::Ok(response),
            3,
        )?))
    }
}

#[derive(Debug)]
struct MigrateCall(FuncBody);

impl EntrypointCall for MigrateCall {}

impl MigrateCall {
    pub fn new() -> Result<Self, serde_json::Error> {
        let response = Response::<Empty>::default();
        Ok(MigrateCall(Self::plain(
            ContractResult::<Response<Empty>>::Ok(response),
            2,
        )?))
    }
}

#[derive(Debug)]
struct QueryCall(FuncBody);

impl EntrypointCall for QueryCall {}

impl QueryCall {
    pub fn new() -> Result<Self, serde_json::Error> {
        let encoded_result = hex::encode("{}");
        Ok(QueryCall(Self::plain(
            ContractResult::<alloc::string::String>::Ok(encoded_result),
            2,
        )?))
    }
}

impl From<ModuleDefinition> for WasmModule {
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

        let mut function_definitions = vec![
            // fn allocate(size: usize) -> u32;
            Function {
                name: "allocate".into(),
                params: vec![ValueType::I32],
                result: Some(ValueType::I32),
                definition: FuncBody::new(
                    vec![Local::new(1, ValueType::I32)],
                    Instructions::new(vec![
                        // reserve space
                        // save offset as global offset ptr + 12
                        Instruction::GetGlobal(0),
                        Instruction::I32Const(12),
                        Instruction::GetGlobal(0),
                        Instruction::I32Add,
                        Instruction::I32Store(0, 0),
                        // set capacity to input reserve size
                        Instruction::GetGlobal(0),
                        Instruction::I32Const(4),
                        Instruction::I32Add,
                        Instruction::GetLocal(0),
                        Instruction::I32Store(0, 0),
                        // set length to 0
                        Instruction::GetGlobal(0),
                        Instruction::I32Const(8),
                        Instruction::I32Add,
                        Instruction::I32Const(0),
                        Instruction::I32Store(0, 0),
                        // save global offset ptr to local_var_1
                        Instruction::GetGlobal(0),
                        Instruction::SetLocal(1),
                        // increase global offset ptr by (12 + capacity)
                        Instruction::GetGlobal(0),
                        Instruction::I32Const(12),
                        Instruction::I32Add,
                        Instruction::GetLocal(0),
                        Instruction::I32Add,
                        Instruction::SetGlobal(0),
                        // increase global offset ptr by allocated size
                        Instruction::GetLocal(1),
                        Instruction::Return,
                        Instruction::End,
                    ]),
                ),
            },
            // fn instantiate(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32;
            Function {
                name: "instantiate".into(),
                params: vec![ValueType::I32, ValueType::I32, ValueType::I32],
                result: Some(ValueType::I32),
                definition: def.instantiate_call.0,
            },
            // fn execute(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32;
            Function {
                name: "execute".into(),
                params: vec![ValueType::I32, ValueType::I32, ValueType::I32],
                result: Some(ValueType::I32),
                definition: def.execute_call.0,
            },
            // fn migrate(env_ptr: u32, msg_ptr: u32) -> u32;
            Function {
                name: "migrate".into(),
                params: vec![ValueType::I32, ValueType::I32],
                result: Some(ValueType::I32),
                definition: def.migrate_call.0,
            },
            // fn deallocate(pointer: u32);
            Function {
                name: "deallocate".into(),
                params: vec![ValueType::I32],
                result: None,
                definition: FuncBody::new(Vec::new(), Instructions::empty()),
            },
            // fn query(env_ptr: u32, msg_ptr: u32) -> u32;
            Function {
                name: "query".into(),
                params: vec![ValueType::I32, ValueType::I32],
                result: Some(ValueType::I32),
                definition: def.query_call.0,
            },
            // dummy function to increase the binary size
            Function {
                name: "dummy_fn".into(),
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
            Function {
                name: "interface_version_8".into(),
                params: vec![],
                result: None,
                definition: FuncBody::new(Vec::new(), Instructions::empty()),
            },
        ];

        for function in def.additional_functions {
            function_definitions.push(function);
        }

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
