use super::VmError;
use bech32::{self, FromBase32, ToBase32, Variant};
use cosmwasm_std::CanonicalAddr;
use cosmwasm_vm::vm::{VmAddressOf, VmCanonicalAddressOf, VmErrorOf};
use cosmwasm_vm_wasmi::WasmiBaseVM;

pub trait AddressHandler {
    fn addr_validate<V: WasmiBaseVM>(input: &str) -> Result<(), VmErrorOf<V>>
    where
        VmErrorOf<V>: From<VmError>,
    {
        let canonical_addr = Self::addr_canonicalize::<V>(input)?;
        let addr = Self::addr_humanize::<V>(&canonical_addr)?;
        if addr.into().as_ref() == input {
            Ok(())
        } else {
            Err(VmError::InvalidAddress.into())
        }
    }

    fn addr_canonicalize<V: WasmiBaseVM>(
        input: &str,
    ) -> Result<VmCanonicalAddressOf<V>, VmErrorOf<V>>
    where
        VmErrorOf<V>: From<VmError>;

    fn addr_humanize<V: WasmiBaseVM>(
        addr: &VmCanonicalAddressOf<V>,
    ) -> Result<VmAddressOf<V>, VmErrorOf<V>>
    where
        VmErrorOf<V>: From<VmError>;
}

pub trait CosmosAddressHandler {
    const PREFIX: &'static str;
}

impl<T: CosmosAddressHandler> AddressHandler for T {
    fn addr_canonicalize<V: WasmiBaseVM>(
        input: &str,
    ) -> Result<VmCanonicalAddressOf<V>, VmErrorOf<V>>
    where
        VmErrorOf<V>: From<VmError>,
    {
        // TODO(aeryz): check if we need to check if the data size is 20 or 32.
        // We don't care about the data part. As long as it is a valid bech32, it's fine.
        let (hrp, data, _) = bech32::decode(input).map_err(|_| VmError::DecodingFailure)?;
        let data = Vec::<u8>::from_base32(&data).map_err(|_| VmError::InvalidAddress)?;

        if hrp != T::PREFIX {
            return Err(VmError::InvalidAddress.into());
        }

        data.try_into()
    }

    fn addr_humanize<V: WasmiBaseVM>(
        addr: &VmCanonicalAddressOf<V>,
    ) -> Result<VmAddressOf<V>, VmErrorOf<V>>
    where
        VmErrorOf<V>: From<VmError>,
    {
        let canonical_addr: CanonicalAddr = addr.clone().into();
        bech32::encode(
            Self::PREFIX,
            Into::<Vec<u8>>::into(canonical_addr).to_base32(),
            Variant::Bech32,
        )
        .map_err(|_| VmError::EncodingFailure)?
        .try_into()
    }
}

pub struct JunoAddrHandler;

impl CosmosAddressHandler for JunoAddrHandler {
    const PREFIX: &'static str = "juno";
}

pub struct WasmAddressHandler;

impl CosmosAddressHandler for WasmAddressHandler {
    const PREFIX: &'static str = "wasm";
}

pub struct SubstrateAddressHandler;

impl AddressHandler for SubstrateAddressHandler {
    fn addr_canonicalize<V: WasmiBaseVM>(
        input: &str,
    ) -> Result<VmCanonicalAddressOf<V>, VmErrorOf<V>>
    where
        VmErrorOf<V>: From<VmError>,
    {
        bs58::decode(input)
            .into_vec()
            .map_err(|_| VmError::DecodingFailure)?
            .try_into()
    }

    fn addr_humanize<V: WasmiBaseVM>(
        addr: &VmCanonicalAddressOf<V>,
    ) -> Result<VmAddressOf<V>, VmErrorOf<V>>
    where
        VmErrorOf<V>: From<VmError>,
    {
        let addr: Vec<u8> = Into::<CanonicalAddr>::into(addr.clone()).into();
        bs58::encode(&addr).into_string().try_into()
    }
}
