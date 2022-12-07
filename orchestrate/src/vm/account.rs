use super::{AddressHandler, VmError};
use alloc::vec::Vec;
use core::fmt::Display;
use cosmwasm_std::{Addr, Binary, CanonicalAddr};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
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
#[allow(clippy::module_name_repetitions)]
pub struct Account(pub Addr);

impl Display for Account {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <Addr as Display>::fmt(&self.0, f)
    }
}

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

impl From<Account> for String {
    fn from(account: Account) -> Self {
        account.0.into_string()
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
    #[must_use]
    pub fn generate<AH: AddressHandler>(code_hash: &[u8], message: &[u8]) -> Result<Self, VmError> {
        let addr = AH::addr_generate([code_hash, message])?;
        Ok(Self::unchecked(addr))
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
    #[must_use]
    pub fn generate_by_code<AH: AddressHandler>(
        code: &[u8],
        message: &[u8],
    ) -> Result<Self, VmError> {
        let code_hash = Sha256::new().chain_update(code).finalize();
        Self::generate::<AH>(&code_hash[..], message)
    }

    /// Generates an `Account` based on the provided `seed`
    #[must_use]
    pub fn generate_from_seed<AH: AddressHandler>(seed: &str) -> Result<Self, VmError> {
        let addr = AH::addr_generate([seed.as_ref()])?;
        Ok(Self::unchecked(addr))
    }
}
