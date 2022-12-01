use super::VmError;
use bech32::{self, FromBase32, ToBase32, Variant};
use sha2::{Digest, Sha256};

// If secp256k1 is used
const COSMOS_ADDR_LEN: usize = 20;
// If secp256r1 is used
const COSMOS_ADDR_LEN_2: usize = 32;
const SUBSTRATE_ADDR_LEN: usize = 32;

pub trait AddressHandler {
    fn addr_validate(input: &str) -> Result<(), VmError> {
        let canonical_addr = Self::addr_canonicalize(input)?;
        let addr = Self::addr_humanize(&canonical_addr)?;
        if addr.as_str() == input {
            Ok(())
        } else {
            Err(VmError::InvalidAddress)
        }
    }

    fn addr_canonicalize(input: &str) -> Result<Vec<u8>, VmError>;

    fn addr_humanize(addr: &[u8]) -> Result<String, VmError>;

    fn addr_generate<'a, I: IntoIterator<Item = &'a [u8]>>(iter: I) -> Result<String, VmError>;
}

pub trait CosmosAddressHandler {
    const PREFIX: &'static str;
}

impl<T: CosmosAddressHandler> AddressHandler for T {
    fn addr_canonicalize(input: &str) -> Result<Vec<u8>, VmError> {
        // We don't care about the data part. As long as it is a valid bech32, it's fine.
        // NOTE(aeryz): We can verify `secp256k/r1` here
        let (hrp, data, _) = bech32::decode(input).map_err(|_| VmError::DecodingFailure)?;
        let data = Vec::<u8>::from_base32(&data).map_err(|_| VmError::InvalidAddress)?;

        if hrp != T::PREFIX || (data.len() != COSMOS_ADDR_LEN && data.len() != COSMOS_ADDR_LEN_2) {
            return Err(VmError::InvalidAddress);
        }

        Ok(data)
    }

    fn addr_humanize(addr: &[u8]) -> Result<String, VmError> {
        if addr.len() != COSMOS_ADDR_LEN && addr.len() != COSMOS_ADDR_LEN_2 {
            return Err(VmError::InvalidAddress);
        }
        bech32::encode(Self::PREFIX, addr.to_base32(), Variant::Bech32)
            .map_err(|_| VmError::EncodingFailure)
    }

    fn addr_generate<'a, I: IntoIterator<Item = &'a [u8]>>(iter: I) -> Result<String, VmError> {
        let mut hash = Sha256::new();
        for data in iter {
            hash = hash.chain_update(data);
        }
        Self::addr_humanize(hash.finalize().as_ref())
    }
}

pub struct JunoAddressHandler;

impl CosmosAddressHandler for JunoAddressHandler {
    const PREFIX: &'static str = "juno";
}

pub struct WasmAddressHandler;

impl CosmosAddressHandler for WasmAddressHandler {
    const PREFIX: &'static str = "wasm";
}

pub struct SubstrateAddressHandler;

impl AddressHandler for SubstrateAddressHandler {
    // NOTE(aeryz): We might check version on checksum bytes as well
    fn addr_canonicalize(input: &str) -> Result<Vec<u8>, VmError> {
        let addr = bs58::decode(input)
            .into_vec()
            .map_err(|_| VmError::DecodingFailure)?;

        // We compare against +3 here because of the version and checksum bytes
        if addr.len() != SUBSTRATE_ADDR_LEN + 3 {
            return Err(VmError::InvalidAddress);
        }

        Ok(addr)
    }

    fn addr_humanize(addr: &[u8]) -> Result<String, VmError> {
        if addr.len() != SUBSTRATE_ADDR_LEN + 3 {
            return Err(VmError::InvalidAddress);
        }
        Ok(bs58::encode(&addr).into_string())
    }

    fn addr_generate<'a, I: IntoIterator<Item = &'a [u8]>>(iter: I) -> Result<String, VmError> {
        let mut hash = Sha256::new();
        for data in iter {
            hash = hash.chain_update(data);
        }
        let mut hash = hash.finalize().to_vec();
        // Version byte for generic substrate
        hash.insert(0, 42);
        // Two additional checksum bytes
        hash.push(0);
        hash.push(0);
        Self::addr_humanize(hash.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrate_handler() {
        // generated address is valid
        let addr = SubstrateAddressHandler::addr_generate(["hello world".as_bytes()]).unwrap();
        assert!(SubstrateAddressHandler::addr_validate(&addr).is_ok());

        // polkadot
        assert!(SubstrateAddressHandler::addr_validate(
            "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
        )
        .is_ok());

        // kusama
        assert!(SubstrateAddressHandler::addr_validate(
            "HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F"
        )
        .is_ok());

        // substrate generic
        assert!(SubstrateAddressHandler::addr_validate(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )
        .is_ok());
    }

    #[test]
    fn cosmos_handler() {
        // generated address is valid
        let addr = JunoAddressHandler::addr_generate(["junojuno".as_bytes()]).unwrap();
        assert!(JunoAddressHandler::addr_validate(&addr).is_ok());

        // juno works
        assert!(
            JunoAddressHandler::addr_validate("juno16g2rahf5846rxzp3fwlswy08fz8ccuwk03k57y")
                .is_ok()
        );

        // other chain's address fails
        assert!(
            JunoAddressHandler::addr_validate("cosmos16g2rahf5846rxzp3fwlswy08fz8ccuwk03k57y")
                .is_err()
        );
    }
}
