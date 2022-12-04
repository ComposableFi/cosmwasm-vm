# Custom Message Handler

`CustomMsg` calls result in `NotSupported` error in the default implementation. But our 
framework is flexible enough to let you define your own custom message logic.


## Implementing a custom message handler

If your chain supports `CosmosMsg::Custom`, you can simply implement the `CustomHandler`
trait in our framework and handle custom messages and queries. Note that your `CustomHandler`
type needs to implement `Clone` because it will get reverted if the transaction fails.

```rust
/// Type that implements the CustomHandler
#[derive(Default, Clone)]
pub struct MyCustomHandler;

/// Custom message type
pub struct MyCustomMessage;

/// Custom query type 
pub struct MyCustomQuery;

impl CustomHandler for MyCustomHandler {
    type QueryCustom = MyCustomQuery;
    type MessageCustom = MyCustomMessage;

    fn handle_message<AH: AddressHandler>(
        vm: &mut Context<Self, AH>,
        message: MyCustomMessage,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, VmError> {
        self.state.db.custom_handler.do_something_with_message(message);
    }

    fn handle_query<AH: AddressHandler>(
        vm: &mut Context<Self, AH>,
        query: MyCustomQuery,
    ) -> Result<SystemResult<CosmwasmQueryResult>, VmError> {
        self.state.db.custom_handler.do_something_with_query(query);
    }
}
```

Then you again need to create an `Api` type which uses `MyCustomHandler`.

```rust
pub type CustomJunoApi<'a, E = Dispatch> = Api<
    'a,
    E,
    JunoAddressHandler,
    State<MyCustomHandler, JunoAddressHandler>,
    Context<'a, MyCustomHandler, JunoAddressHandler>,
>;
```

One more thing is, you need to provide `MyCustomHandler` to the `StateBuilder`.

```rust
let state = StateBuilder::<JunoAddressHandler>::new()
    .add_code(&code)
    .set_custom_handler(MyCustomHandler)
    .build();
```