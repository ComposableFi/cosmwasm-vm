#![feature(let_else)]
#![feature(generic_associated_types)]
#![feature(trait_alias)]
#![cfg_attr(feature = "no_std", no_std)]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

mod api;
pub mod error;
pub mod fetcher;
pub mod ibc;
pub mod vm;

pub use api::*;
