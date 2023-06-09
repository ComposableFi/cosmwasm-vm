
# CosmWasm VM

Experimental, minimalistic, `no_std` friendly abstract virtual machine for CosmWasm contracts execution.

Based on `wasmi` interpeter and can be run in other VM. Allows to host CosmWasm VM inside other Wasm VM. 
In contrast, Cosmos `wasmd` VM can run only on native host.

[Specification](SPEC.md)

## Getting started

- [Install Nix](https://zero-to-nix.com/start/install) and enter the dev env with: `nix develop`.
- Or install latest Rust nightly. 
- Run test suite using: `cargo test`

### Research

Install `flamegraph` (in nix shell already installed)

`RUST_LOG=trace cargo run --bin research --release 2>&1 | tee research.log` and see some output for deep logging.

`RUST_LOG=info cargo run --bin research --release` and see some output long run with coarse grain output.

`flamegraph target/release/research`

Modify `research.rs` as needed.

## `no_std` support

Until release of CW for `no_std`, which is planned with CW 2.0 in September, need maintain no_std forks in this order:
- serde-json-wasm
- cosmwasm-std
- cw-stroage-plus
- cw-plus (package with interfaces, not contracts)

These are required to use cw code in Substrate runtime(for host and precompiles) and compile contracts with `no_std` only wasm crates (when wasm compiled, it can be only `no_std`.

### How to consume forked cw interfaces in contracts?

First option is reference or patch contracts to point to forks.

Other option is to generate schema from interface and generate rust code from schema.

## Authors
  "Hussein Ait Lahcen hussein.aitlahcen@gmail.com"
  "Abdullah Eryuzlu abdullaheryuzlu@gmail.com"
  "Composable Developers"
##  homepage

https://composable.finance
