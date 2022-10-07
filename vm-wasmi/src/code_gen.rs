use alloc::{vec, vec::Vec};
use cosmwasm_minimal_std::{ContractResult, Empty, Response};
use wasm_instrument::parity_wasm::{
    self, builder,
    elements::{
        External, FuncBody,
        Instruction::{self, BrTable},
        Instructions, Internal, Local, Module, Type, ValueType,
    },
};
use wasmi_validation::{validate_module, PlainValidator};

#[derive(Debug)]
pub enum ValidationError {
    Validation(wasmi_validation::Error),
    ExportMustBeAFunction(&'static str),
    EntryPointPointToImport(&'static str),
    ExportDoesNotExists(&'static str),
    ExportWithoutSignature(&'static str),
    ExportWithWrongSignature {
        export_name: &'static str,
        expected_signature: Vec<ValueType>,
        actual_signature: Vec<ValueType>,
    },
    MissingMandatoryExport(&'static str),
    CannotImportTable,
    CannotImportGlobal,
    CannotImportMemory,
    ImportWithoutSignature,
    ImportIsBanned(&'static str, &'static str),
    MustDeclareOneInternalMemory,
    MustDeclareOneTable,
    TableExceedLimit,
    BrTableExceedLimit,
    GlobalsExceedLimit,
    GlobalFloatingPoint,
    LocalFloatingPoint,
    ParamFloatingPoint,
    FunctionParameterExceedLimit,
}

#[derive(PartialEq, Eq)]
pub enum ExportRequirement {
    Mandatory,
    Optional,
}

pub struct CodeValidation<'a>(&'a Module);
impl<'a> CodeValidation<'a> {
    pub fn new(module: &'a Module) -> Self {
        CodeValidation(module)
    }

    pub fn validate_base(self) -> Result<Self, ValidationError> {
        validate_module::<PlainValidator>(self.0, ()).map_err(ValidationError::Validation)?;
        Ok(self)
    }

    pub fn validate_exports(
        self,
        expected_exports: &[(ExportRequirement, &'static str, &'static [ValueType])],
    ) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        let types = module.type_section().map(|ts| ts.types()).unwrap_or(&[]);
        let export_entries = module
            .export_section()
            .map(|is| is.entries())
            .unwrap_or(&[]);
        let func_entries = module
            .function_section()
            .map(|fs| fs.entries())
            .unwrap_or(&[]);
        let fn_space_offset = module
            .import_section()
            .map(|is| is.entries())
            .unwrap_or(&[])
            .iter()
            .filter(|entry| matches!(*entry.external(), External::Function(_)))
            .count();
        for (requirement, name, signature) in expected_exports {
            match (
                requirement,
                export_entries.iter().find(|e| &e.field() == name),
            ) {
                (_, Some(export)) => {
                    let fn_idx = match export.internal() {
                        Internal::Function(ref fn_idx) => Ok(*fn_idx),
                        _ => Err(ValidationError::ExportMustBeAFunction(name)),
                    }?;
                    let fn_idx = match fn_idx.checked_sub(fn_space_offset as u32) {
                        Some(fn_idx) => Ok(fn_idx),
                        None => Err(ValidationError::EntryPointPointToImport(name)),
                    }?;
                    let func_ty_idx = func_entries
                        .get(fn_idx as usize)
                        .ok_or(ValidationError::ExportDoesNotExists(name))?
                        .type_ref();
                    let Type::Function(ref func_ty) = types
                        .get(func_ty_idx as usize)
                        .ok_or(ValidationError::ExportWithoutSignature(name))?;
                    if signature != &func_ty.params() {
                        return Err(ValidationError::ExportWithWrongSignature {
                            export_name: name,
                            expected_signature: signature.to_vec(),
                            actual_signature: func_ty.params().to_vec(),
                        });
                    }
                }
                (ExportRequirement::Mandatory, None) => {
                    return Err(ValidationError::MissingMandatoryExport(name))
                }
                (ExportRequirement::Optional, None) => {}
            }
        }
        Ok(self)
    }

    pub fn validate_imports(
        self,
        import_banlist: &[(&'static str, &'static str)],
    ) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        let types = module.type_section().map(|ts| ts.types()).unwrap_or(&[]);
        let import_entries = module
            .import_section()
            .map(|is| is.entries())
            .unwrap_or(&[]);
        for import in import_entries {
            let type_idx = match import.external() {
                External::Table(_) => Err(ValidationError::CannotImportTable),
                External::Global(_) => Err(ValidationError::CannotImportGlobal),
                External::Memory(_) => Err(ValidationError::CannotImportMemory),
                External::Function(ref type_idx) => Ok(type_idx),
            }?;
            let import_name = import.field();
            let import_module = import.module();
            let Type::Function(_) = types
                .get(*type_idx as usize)
                .ok_or(ValidationError::ImportWithoutSignature)?;
            if let Some((m, f)) = import_banlist
                .iter()
                .find(|(m, f)| m == &import_module && f == &import_name)
            {
                return Err(ValidationError::ImportIsBanned(m, f));
            }
        }
        Ok(self)
    }

    pub fn validate_memory_limit(self) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        if module
            .memory_section()
            .map_or(false, |ms| ms.entries().len() != 1)
        {
            Err(ValidationError::MustDeclareOneInternalMemory)
        } else {
            Ok(self)
        }
    }

    pub fn validate_table_size_limit(self, limit: u32) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        if let Some(table_section) = module.table_section() {
            if table_section.entries().len() > 1 {
                return Err(ValidationError::MustDeclareOneTable);
            }
            if let Some(table_type) = table_section.entries().first() {
                if table_type.limits().initial() > limit {
                    return Err(ValidationError::TableExceedLimit);
                }
            }
        }
        Ok(self)
    }

    pub fn validate_br_table_size_limit(self, limit: u32) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        if let Some(code_section) = module.code_section() {
            for instr in code_section
                .bodies()
                .iter()
                .flat_map(|body| body.code().elements())
            {
                if let BrTable(table) = instr {
                    if table.table.len() > limit as usize {
                        return Err(ValidationError::BrTableExceedLimit);
                    }
                }
            }
        };
        Ok(self)
    }

    pub fn validate_no_floating_types(self) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        if let Some(global_section) = module.global_section() {
            for global in global_section.entries() {
                match global.global_type().content_type() {
                    ValueType::F32 | ValueType::F64 => {
                        return Err(ValidationError::GlobalFloatingPoint)
                    }
                    _ => {}
                }
            }
        }
        if let Some(code_section) = module.code_section() {
            for func_body in code_section.bodies() {
                for local in func_body.locals() {
                    match local.value_type() {
                        ValueType::F32 | ValueType::F64 => {
                            return Err(ValidationError::LocalFloatingPoint)
                        }
                        _ => {}
                    }
                }
            }
        }
        if let Some(type_section) = module.type_section() {
            for wasm_type in type_section.types() {
                match wasm_type {
                    Type::Function(func_type) => {
                        let return_type = func_type.results().get(0);
                        for value_type in func_type.params().iter().chain(return_type) {
                            match value_type {
                                ValueType::F32 | ValueType::F64 => {
                                    return Err(ValidationError::ParamFloatingPoint)
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        Ok(self)
    }

    pub fn validate_global_variable_limit(self, limit: u32) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        if let Some(global_section) = module.global_section() {
            if global_section.entries().len() > limit as usize {
                return Err(ValidationError::GlobalsExceedLimit);
            }
        }
        Ok(self)
    }

    pub fn validate_parameter_limit(self, limit: u32) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        if let Some(type_section) = module.type_section() {
            for Type::Function(func) in type_section.types() {
                if func.params().len() > limit as usize {
                    return Err(ValidationError::FunctionParameterExceedLimit);
                }
            }
        }
        Ok(self)
    }
}

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
            // query function (6)
            .function()
            .signature()
            .with_params(vec![ValueType::I32, ValueType::I32])
            .with_result(ValueType::I32)
            .build()
            .with_body(FuncBody::new(
                Vec::new(),
                Instructions::new(vec![
                    Instruction::I32Const(0),
                    Instruction::Return,
                    Instruction::End,
                ]),
            ))
            .build()
            // dummy interface
            .function()
            .signature()
            .build()
            .with_body(FuncBody::new(Vec::new(), Instructions::empty()))
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
            .build()
            .export()
            .field("interface_version_8")
            .internal()
            .func(func_offset + 6)
            .build()
            .export()
            .field("query")
            .internal()
            .func(func_offset + 5)
            .build();

        let code = contract.build();

        let code = code.into_bytes().unwrap();
        Self { code }
    }
}

const V1_EXPORTS: &'static [(
    ExportRequirement,
    &'static str,
    &'static [parity_wasm::elements::ValueType],
)] = &[
    // We support v1+
    (ExportRequirement::Mandatory, "interface_version_8", &[]),
    // Memory related exports.
    (
        ExportRequirement::Mandatory,
        "allocate",
        &[parity_wasm::elements::ValueType::I32],
    ),
    (
        ExportRequirement::Mandatory,
        "deallocate",
        &[parity_wasm::elements::ValueType::I32],
    ),
    // Contract execution exports.
    (
        ExportRequirement::Mandatory,
        "instantiate",
        // extern "C" fn instantiate(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32;
        &[
            parity_wasm::elements::ValueType::I32,
            parity_wasm::elements::ValueType::I32,
            parity_wasm::elements::ValueType::I32,
        ],
    ),
    (
        ExportRequirement::Mandatory,
        "execute",
        // extern "C" fn execute(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32;
        &[
            parity_wasm::elements::ValueType::I32,
            parity_wasm::elements::ValueType::I32,
            parity_wasm::elements::ValueType::I32,
        ],
    ),
    (
        ExportRequirement::Mandatory,
        "query",
        // extern "C" fn query(env_ptr: u32, msg_ptr: u32) -> u32;
        &[
            parity_wasm::elements::ValueType::I32,
            parity_wasm::elements::ValueType::I32,
        ],
    ),
];

#[test]
fn generated_code_is_pallet_cosmwasm_compatible() {
    let wasm_module: WasmModule = ModuleDefinition::new(100).unwrap().into();
    let module = parity_wasm::elements::Module::from_bytes(&wasm_module.code).unwrap();

    let _ = CodeValidation::new(&module)
        .validate_base()
        .unwrap()
        .validate_memory_limit()
        .unwrap()
        .validate_table_size_limit(4096)
        .unwrap()
        .validate_global_variable_limit(256)
        .unwrap()
        .validate_parameter_limit(128)
        .unwrap()
        .validate_br_table_size_limit(256)
        .unwrap()
        .validate_no_floating_types()
        .unwrap()
        .validate_exports(V1_EXPORTS)
        .unwrap()
        // env.gas is banned as injected by instrumentation
        .validate_imports(&[("env", "gas")])
        .unwrap();
}
