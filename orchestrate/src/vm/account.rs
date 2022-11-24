use super::VmError;
use alloc::format;
use alloc::vec::Vec;
use cosmwasm_std::{Addr, Binary, CanonicalAddr};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct CanonicalAccount(pub CanonicalAddr);

impl TryFrom<Vec<u8>> for CanonicalAccount {
    type Error = VmError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(CanonicalAccount(CanonicalAddr(Binary::from(value))))
    }
}

impl From<CanonicalAccount> for Vec<u8> {
    fn from(addr: CanonicalAccount) -> Self {
        addr.0.into()
    }
}

impl From<CanonicalAccount> for CanonicalAddr {
    fn from(addr: CanonicalAccount) -> Self {
        addr.0
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Account(pub Addr);

impl TryFrom<Addr> for Account {
    type Error = VmError;
    fn try_from(value: Addr) -> Result<Self, Self::Error> {
        Ok(Account(value))
    }
}

impl TryFrom<String> for Account {
    type Error = VmError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Account(Addr::unchecked(value.as_str())))
    }
}

impl From<Account> for Addr {
    fn from(Account(addr): Account) -> Self {
        addr
    }
}

impl Account {
    pub fn unchecked<A: Into<String>>(addr: A) -> Self {
        Account(Addr::unchecked(addr))
    }

    /// Generates an `Account` based on `code_hash` and `message`
    ///
    /// * `code_hash` - Hash of the contract code
    /// * `message` - Raw instantiate message
    ///
    /// The address is generated with the algorithm: `Sha1(code_hash + message)`
    pub fn generate(code_hash: &[u8], message: &[u8]) -> Self {
        let hash = Sha1::new()
            .chain_update(code_hash)
            .chain_update(message)
            .finalize();
        Account(Addr::unchecked(format!("{:x}", hash)))
    }

    /// Generates an `Account` based on `code` and `message`
    ///
    /// * `code` - Contract code
    /// * `message` - Raw instantiate message
    ///
    /// Note that the `Account` generation algorithm is only based on these two
    /// parameters which has nothing to do with the current runtime. This means
    /// that by using this function, one can generate the `Account` prior to
    /// execution.
    /// See [`Self::generate`] for the generation algorithm
    pub fn generate_by_code(code: &[u8], message: &[u8]) -> Self {
        let code_hash = Sha1::new().chain_update(code).finalize();
        Self::generate(&code_hash[..], message)
    }
}
