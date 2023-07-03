use super::{bank, Account};
use alloc::string::String;
use core::fmt::Display;
use cosmwasm_vm::{
    executor::ExecutorError,
    memory::{MemoryReadError, MemoryWriteError},
    system::{CosmwasmCodeId, SystemError},
};
use cosmwasm_vm_wasmi::WasmiVMError;

#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum VmError {
    Interpreter(String),
    VMError(WasmiVMError),
    BankError(bank::Error),
    CodeNotFound(CosmwasmCodeId),
    ContractNotFound(Account),
    InvalidAddress,
    InvalidAccountFormat,
    NoCustomQuery,
    NoCustomMessage,
    Unsupported,
    OutOfGas,
    CryptoError,
    IteratorDoesNotExist,
    AlreadyInstantiated,
    CannotSerialize,
    CannotDeserialize,
    UnknownIbcChannel,
    IbcChannelOpenFailure(String),
    Generic(String),
    EncodingFailure,
    DecodingFailure,
    NotAuthorized,
}

impl wasmi::core::HostError for VmError {}

impl From<wasmi::Error> for VmError {
    fn from(e: wasmi::Error) -> Self {
        match e {
            wasmi::Error::Trap(ref trap) => {
                if let Some(err) = trap.downcast_ref::<VmError>() {
                    err.clone()
                } else {
                    Self::Interpreter(e.to_string())
                }
            }
            e => Self::Interpreter(e.to_string()),
        }
    }
}

impl From<WasmiVMError> for VmError {
    fn from(e: WasmiVMError) -> Self {
        VmError::VMError(e)
    }
}

impl From<SystemError> for VmError {
    fn from(e: SystemError) -> Self {
        VmError::VMError(e.into())
    }
}

impl From<ExecutorError> for VmError {
    fn from(e: ExecutorError) -> Self {
        VmError::VMError(e.into())
    }
}

impl From<MemoryReadError> for VmError {
    fn from(e: MemoryReadError) -> Self {
        VmError::VMError(e.into())
    }
}

impl From<MemoryWriteError> for VmError {
    fn from(e: MemoryWriteError) -> Self {
        VmError::VMError(e.into())
    }
}

impl From<bank::Error> for VmError {
    fn from(e: bank::Error) -> Self {
        Self::BankError(e)
    }
}

impl Display for VmError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
