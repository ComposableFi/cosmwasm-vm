# CosmWasm VM

Experimental, minimalistic, `no_std` friendly abstract virtual machine for CosmWasm contracts execution.

### Getting started

- [Install Nix](https://zero-to-nix.com/start/install) and enter the dev env with: `nix develop`.
- Or install latest Rust nightly. 
- Run test suite using: `cargo test`

### Research

Install `flamegraph` (in nix shell already installed)

`RUST_LOG=trace cargo run --bin research --release 2>&1 | tee research.log` and see some output for deep logging.

`RUST_LOG=info cargo run --bin research --release` and see some output long run with coarse grain output.

`flamegraph target/release/research`

Modify `research.rs` as needed.

