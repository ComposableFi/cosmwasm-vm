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
    additional_binary_size: usize,
}

/// A wasm module ready to be put on chain.
#[derive(Clone)]
pub struct WasmModule {
    pub code: Vec<u8>,
}

impl ModuleDefinition {
    pub fn new(additional_binary_size: usize) -> Result<Self, ()> {
        Ok(Self {
            instantiate_call: InstantiateCall::new()?,
            execute_call: ExecuteCall::new()?,
            additional_binary_size,
        })
    }
}

trait EntrypointCall {
    fn plain() -> Result<FuncBody, ()> {
        let response = Response::<Empty>::default();
        let result = serde_json::to_string(&ContractResult::<Response<Empty>>::Ok(response))
            .map_err(|_| ())?;

        let instructions = vec![
            vec![
                // Allocate space for instantiate_msg
                Instruction::I32Const(result.len() as i32),
                Instruction::Call(0),
                // we save the ptr to local_var_4
                Instruction::SetLocal(4),
                Instruction::GetLocal(4),
                // now we should set the length to instantiate_result.len()
                Instruction::I32Const(8),
                Instruction::I32Add,
                Instruction::I32Const(result.len() as i32),
                Instruction::I32Store(0, 0),
                Instruction::GetLocal(4),
                // returned ptr to { offset: i32, capacity: i32, length: i32 }
                Instruction::I32Load(0, 0),
                // now we load offset and save it to local_var_3
                Instruction::SetLocal(3),
                Instruction::GetLocal(3),
            ],
            {
                let mut instructions = Vec::new();
                for c in result.chars() {
                    instructions.extend(vec![
                        Instruction::GetLocal(3),
                        Instruction::I32Const(c as i32),
                        Instruction::I32Store(0, 0),
                        Instruction::GetLocal(3),
                        Instruction::I32Const(1),
                        Instruction::I32Add,
                        Instruction::SetLocal(3),
                    ]);
                }
                instructions
            },
            vec![
                Instruction::GetLocal(4),
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
    pub fn new() -> Result<Self, ()> {
        Ok(ExecuteCall(Self::plain()?))
    }
}

#[derive(Debug)]
struct InstantiateCall(FuncBody);

impl EntrypointCall for InstantiateCall {}

impl InstantiateCall {
    pub fn new() -> Result<Self, ()> {
        Ok(InstantiateCall(Self::plain()?))
    }
}

impl From<ModuleDefinition> for WasmModule {
    fn from(def: ModuleDefinition) -> Self {
        let func_offset = 0;

        let contract = builder::module()
            // Generate memory
            .memory()
            .build()
            .global()
            .with_type(ValueType::I32)
            .mutable()
            .init_expr(Instruction::I32Const(0))
            .build()
            // allocate function (1) (i32) -> i32
            .function()
            .signature()
            .with_param(ValueType::I32)
            .with_result(ValueType::I32)
            .build()
            .with_body(FuncBody::new(
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
            ))
            .build()
            // instantiate function (2) (i32, i32, i32) -> i32
            .function()
            .signature()
            .with_params(vec![ValueType::I32, ValueType::I32, ValueType::I32])
            .with_result(ValueType::I32)
            .build()
            .with_body(def.instantiate_call.0)
            .build()
            // execute function (3) (i32, i32, i32) -> i32
            .function()
            .signature()
            .with_params(vec![ValueType::I32, ValueType::I32, ValueType::I32])
            .with_result(ValueType::I32)
            .build()
            .with_body(def.execute_call.0)
            .build()
            // deallocate function (4) (i32)
            .function()
            .signature()
            .with_param(ValueType::I32)
            .build()
            .with_body(FuncBody::new(Vec::new(), Instructions::empty()))
            .build()
            // dummy function (5)
            .function()
            .signature()
            .build()
            .with_body(FuncBody::new(
                Vec::new(),
                Instructions::new({
                    let mut nops = vec![Instruction::Nop; def.additional_binary_size];
                    nops.push(Instruction::End);
                    nops
                }),
            ))
            .build()
            .export()
            .field("allocate")
            .internal()
            .func(func_offset)
            .build()
            .export()
            .field("instantiate")
            .internal()
            .func(func_offset + 1)
            .build()
            .export()
            .field("execute")
            .internal()
            .func(func_offset + 2)
            .build()
            .export()
            .field("deallocate")
            .internal()
            .func(func_offset + 3)
            .build()
            .export()
            .field("dummy_fn")
            .internal()
            .func(func_offset + 4)
            .build()
            .export()
            .field("memory")
            .internal()
            .memory(0)
            .build();

        let code = contract.build();

        let code = code.into_bytes().unwrap();
        Self { code }
    }
}
