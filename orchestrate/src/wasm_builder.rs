use super::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Compile contracts to `wasm` binaries.
/// This is meant to be used prior to the test execution. Otherwise, the users
/// would need to compile their contracts everytime they change it.
pub struct WasmLoader {
    package_name: String,
    contract_name: String,
    binary_path: String,
    compile_command: Option<Command>,
}

/// Default output directory of the `wasm` binary.
const DEFAULT_WASM_BINARY_PATH: &str = "target/wasm32-unknown-unknown/release";

impl WasmLoader {
    #[must_use]
    pub fn new<S: Into<String> + Clone>(package_name: S) -> Self {
        Self {
            package_name: package_name.clone().into(),
            contract_name: package_name.into(),
            binary_path: DEFAULT_WASM_BINARY_PATH.into(),
            compile_command: None,
        }
    }

    /// Set the package name to be compiled.
    /// This will be given to as value to `--package`. (If the default compilation command is used)
    #[must_use]
    pub fn package<S: Into<String>>(mut self, package_name: S) -> Self {
        self.package_name = package_name.into();
        self
    }

    /// Set the contract name to be read.
    /// This will be used to get the compiled wasm binary from the path: `{binary_path}/{contract_name}.wasm`
    #[must_use]
    pub fn contract<S: Into<String>>(mut self, contract_name: S) -> Self {
        self.contract_name = contract_name.into();
        self
    }

    /// Set the compilation command to be executed.
    /// This will be executed to compile the desired contract.
    #[must_use]
    pub fn command(mut self, compile_command: Command) -> Self {
        self.compile_command = Some(compile_command);
        self
    }

    /// Set the path to the output `wasm` binary.
    /// This will be used to get the compiled wasm binary from the path: `{binary_path}/{contract_name}.wasm`
    #[must_use]
    pub fn binary_path<S: Into<String>>(mut self, path: S) -> Self {
        self.binary_path = path.into();
        self
    }

    /// Compile and load the `wasm` binary.
    pub fn load(self) -> Result<Vec<u8>, Error> {
        let mut default_command = Command::new("cargo");
        let _ = default_command.args([
            "build",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "--package",
            &self.package_name,
        ]);

        let mut command = self.compile_command.unwrap_or(default_command);

        if !command
            .status()
            .map_err(|_| Error::CannotCompileWasm)?
            .success()
        {
            return Err(Error::CannotCompileWasm);
        }

        fs::read(Path::new(&format!(
            "{}/{}.wasm",
            self.binary_path, self.contract_name
        )))
        .map_err(|_| Error::CannotCompileWasm)
    }
}
