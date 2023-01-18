use super::version::Export;
use alloc::vec::Vec;
use wasm_instrument::parity_wasm::elements::{
    ExportSection, External, FunctionSection, ImportSection, Instruction, Internal, Module, Type,
    TypeSection, ValueType,
};
use wasmi_validation::Validator;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum ValidationError {
    Validation(wasmi_validation::Error),
    ExportMustBeAFunction(&'static str),
    EntryPointPointToImport(&'static str),
    ExportDoesNotExist(&'static str),
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

#[allow(clippy::module_name_repetitions)]
pub struct CodeValidation<'a>(&'a Module);

impl<'a> CodeValidation<'a> {
    #[must_use]
    pub fn new(module: &'a Module) -> Self {
        CodeValidation(module)
    }

    /// Middleware function for `wasmi_validation::validate_module`
    ///
    /// * `input`: Custom input to validator
    pub fn validate_module<V: Validator>(
        self,
        input: <V as Validator>::Input,
    ) -> Result<Self, ValidationError> {
        wasmi_validation::validate_module::<V>(self.0, input)
            .map_err(ValidationError::Validation)?;
        Ok(self)
    }

    /// Checks if the expected exports exist and correct.
    ///
    /// If the export is mandatory, then it has to be present in the wasm module it's signature must
    /// be correct. In both cases, exports need to have the identical signatures as well.
    pub fn validate_exports(self, expected_exports: &[Export]) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        let types = module
            .type_section()
            .map_or(Default::default(), TypeSection::types);
        let export_entries = module
            .export_section()
            .map_or(Default::default(), ExportSection::entries);
        let func_entries = module
            .function_section()
            .map_or(Default::default(), FunctionSection::entries);
        let fn_space_offset = module
            .import_section()
            .map_or(Default::default(), ImportSection::entries)
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
                    #[allow(clippy::cast_possible_truncation)]
                    let fn_idx = match fn_idx.checked_sub(fn_space_offset as u32) {
                        Some(fn_idx) => Ok(fn_idx),
                        None => Err(ValidationError::EntryPointPointToImport(name)),
                    }?;
                    let func_ty_idx = func_entries
                        .get(fn_idx as usize)
                        .ok_or(ValidationError::ExportDoesNotExist(name))?
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

    /// Check if the module imports the correct externals and avoids importing
    /// the banned imports.
    ///
    /// Currently only functions are imported, so it will fail if any other
    /// external is imported.
    pub fn validate_imports(
        self,
        import_banlist: &[(&'static str, &'static str)],
    ) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        let types = module
            .type_section()
            .map_or(Default::default(), TypeSection::types);
        let import_entries = module
            .import_section()
            .map_or(Default::default(), ImportSection::entries);
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

    /// Verify if the memory is setup correctly.
    ///
    /// Currently only a single memory section is supported.
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

    /// Make sure that there is a table and the table's entries are smaller than the `limit`.
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

    /// Make sure that the br table length doesn't exceed the `limit`.
    pub fn validate_br_table_size_limit(self, limit: u32) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        if let Some(code_section) = module.code_section() {
            for instr in code_section
                .bodies()
                .iter()
                .flat_map(|body| body.code().elements())
            {
                if let Instruction::BrTable(table) = instr {
                    if table.table.len() > limit as usize {
                        return Err(ValidationError::BrTableExceedLimit);
                    }
                }
            }
        };
        Ok(self)
    }

    /// Make sure that the count of global variables don't exceed the `limit`.
    pub fn validate_global_variable_limit(self, limit: u32) -> Result<Self, ValidationError> {
        let CodeValidation(module) = self;
        if let Some(global_section) = module.global_section() {
            if global_section.entries().len() > limit as usize {
                return Err(ValidationError::GlobalsExceedLimit);
            }
        }
        Ok(self)
    }

    /// Make sure that there is no floating types. Floating point types yield to undeterministic
    /// wasm builds. That's why they are undesirable.
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

    /// Make sure that the count of parameters in functions do not exceed the `limit`.
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
