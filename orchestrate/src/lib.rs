#![feature(trait_alias)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

mod api;
pub mod error;
#[cfg(feature = "std")]
pub mod fetcher;
pub mod ibc;
pub mod vm;
#[cfg(feature = "std")]
mod wasm_builder;

pub use api::*;
pub use cosmwasm_std;
#[cfg(feature = "std")]
pub use wasm_builder::*;
