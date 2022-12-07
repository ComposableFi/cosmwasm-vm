use cosmwasm_orchestrate::{
    fetcher::FileFetcher,
    vm::{Account, AddressHandler, Context, CosmosAddressHandler, State, VmError},
    *,
};
use sha2::{Digest, Sha256};

const REFLECT_URL: &'static str =
    "https://github.com/CosmWasm/cosmwasm/releases/download/v1.1.8/reflect.wasm";

pub struct CustomCosmosAddressHandler;

impl CosmosAddressHandler for CustomCosmosAddressHandler {
    const PREFIX: &'static str = "cosmos";
}

pub type CosmosApi<'a, E = Dispatch> = Api<
    'a,
    E,
    CustomCosmosAddressHandler,
    State<(), CustomCosmosAddressHandler>,
    Context<'a, (), CustomCosmosAddressHandler>,
>;

#[allow(unused)]
struct DummyAddressHandler;

impl AddressHandler for DummyAddressHandler {
    fn addr_canonicalize(input: &str) -> Result<Vec<u8>, VmError> {
        // We just convert the address into binary
        Ok(input.as_bytes().into())
    }

    fn addr_humanize(addr: &[u8]) -> Result<String, VmError> {
        String::from_utf8(addr.into()).map_err(|_| VmError::InvalidAddress)
    }

    fn addr_generate<'a, I: IntoIterator<Item = &'a [u8]>>(iter: I) -> Result<String, VmError> {
        // Just hash the inputs
        let mut hash = Sha256::new();
        for data in iter {
            hash = hash.chain_update(data);
        }
        Self::addr_humanize(hash.finalize().as_ref())
    }
}

#[tokio::main]
async fn main() {
    let code = FileFetcher::from_url(REFLECT_URL).await.unwrap();
    let sender = Account::generate_from_seed::<CustomCosmosAddressHandler>("sender").unwrap();
    let mut state = StateBuilder::<CustomCosmosAddressHandler>::new()
        .add_code(&code)
        .build();
    let _ = <CosmosApi>::instantiate_raw(
        &mut state,
        1,
        None,
        block(),
        None,
        info(&sender),
        100_000_000,
        r#"{}"#.as_bytes(),
    )
    .unwrap();
}
