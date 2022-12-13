use cosmwasm_orchestrate::{
    fetcher::FileFetcher,
    vm::{Account, AddressHandler, Context, CustomHandler, JunoAddressHandler, State, VmError},
    *,
};
use cosmwasm_std::{Binary, Event, SystemResult};
use cosmwasm_vm::executor::CosmwasmQueryResult;
use serde::Deserialize;

const REFLECT_URL: &'static str =
    "https://github.com/CosmWasm/cosmwasm/releases/download/v1.1.8/reflect.wasm";

#[derive(Default, Clone)]
pub struct MyCustomHandler {}

impl MyCustomHandler {
    fn do_something_with_message(&self, message: MyCustomMessage) {
        println!("MESSAGE: {:?}", message);
    }

    fn do_something_with_query(&self, query: MyCustomQuery) {
        println!("QUERY: {:?}", query);
    }
}

/// Custom message type
#[derive(Debug, Deserialize)]
pub struct MyCustomMessage;

/// Custom query type
#[derive(Debug, Deserialize)]
pub struct MyCustomQuery;

impl CustomHandler for MyCustomHandler {
    type QueryCustom = MyCustomQuery;
    type MessageCustom = MyCustomMessage;

    fn handle_message<AH: AddressHandler>(
        vm: &mut Context<Self, AH>,
        message: MyCustomMessage,
        _event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, VmError> {
        vm.state
            .db
            .custom_handler
            .do_something_with_message(message);
        Ok(None)
    }

    fn handle_query<AH: AddressHandler>(
        vm: &mut Context<Self, AH>,
        query: MyCustomQuery,
    ) -> Result<SystemResult<CosmwasmQueryResult>, VmError> {
        vm.state.db.custom_handler.do_something_with_query(query);
        Ok(SystemResult::Ok(CosmwasmQueryResult::Ok(vec![].into())))
    }
}

pub type CustomJunoApi<'a, E = Dispatch> = Api<
    'a,
    E,
    JunoAddressHandler,
    State<MyCustomHandler, JunoAddressHandler>,
    Context<'a, MyCustomHandler, JunoAddressHandler>,
>;

#[tokio::main]
async fn main() {
    let code = FileFetcher::from_url(REFLECT_URL).await.unwrap();
    let sender = Account::generate_from_seed::<JunoAddressHandler>("sender").unwrap();
    let mut state = StateBuilder::<JunoAddressHandler, MyCustomHandler>::new()
        .add_code(&code)
        .set_custom_handler(MyCustomHandler {})
        .build();
    let _ = <CustomJunoApi>::instantiate_raw(
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
