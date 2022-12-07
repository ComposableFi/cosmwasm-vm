# Address Handlers

Throughout this documentation, you see that we always use `JunoApi`. But there are 
few other API's as well like `WasmApi`, `SubstrateApi`, etc. The only difference between
this API's is how they handle the address generation, validation and canonicalization.

For example, Cosmos API's like `JunoApi` or `WasmApi` uses `Bech32` encoding and `JunoApi` uses
`juno` as prefix and `WasmApi` uses `wasm` as prefix.

## Creating your own Cosmos address handler

Cosmos address handlers are implementing the `CosmosAddressHandler` trait which
handles the `Bech32` stuff under the hood. The only thing that you want to specify
is the `PREFIX` constant which is the prefix value in `Bech32` encoding.

Let's create an Address Handler for `CoolChain` where the prefix is `cool`:

```rust
pub struct CoolAddressHandler;

impl CosmosAddressHandler for CoolAddressHandler {
    const PREFIX: &'static str = "cool";
}
```

For ease of use, you can also define this API:

```rust
pub type CoolApi<'a, E = Dispatch> = Api<
    'a,
    E,
    CoolAddressHandler,
    State<(), CoolAddressHandler>,
    Context<'a, (), CoolAddressHandler>,
>;
```

From now on, you can generate account addresses by using `CoolAddressHandler`:

```rust
Account::generate_from_seed::<CoolAddressHandler>("sender").unwrap();
```

And you will use the `CoolApi` for API calls:

```rust
<CoolApi>::instantiate(..);
```

## Implementing an address handler from scratch

You can also implement an address handler from scratch by implementing `AddressHandler` trait.

Let's implement a dummy address handler which works with `String` addresses without any restrictions.

```rust
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
```

Then follow the above steps to use it in your tests and that's all.
