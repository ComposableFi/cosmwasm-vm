// host.rs ---

// Copyright (C) 2022 Hussein Ait-Lahcen

// Author: Hussein Ait-Lahcen <hussein.aitlahcen@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the sale,
// use or other dealings in this Software without prior written authorization.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use core::fmt::Debug;

use alloc::string::String;
use cosmwasm_minimal_std::{
    Binary, ContractInfoResponse, CosmwasmQueryResult, Event, SystemResult,
};

pub type HostErrorOf<T> = <T as Host>::Error;
pub type HostQueryCustomOf<T> = <T as Host>::QueryCustom;
pub type HostMessageCustomOf<T> = <T as Host>::MessageCustom;

pub trait Host {
    type Key;
    type Value;
    type QueryCustom: serde::de::DeserializeOwned + Debug;
    type MessageCustom: serde::de::DeserializeOwned + Debug;
    type Address;
    type Error;
    fn db_read(&mut self, key: Self::Key) -> Result<Option<Self::Value>, Self::Error>;
    fn db_write(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error>;
    fn abort(&mut self, message: String) -> Result<(), Self::Error>;
    fn query_custom(
        &mut self,
        query: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, Self::Error>;
    fn message_custom(
        &mut self,
        message: Self::MessageCustom,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error>;
    fn query_raw(
        &mut self,
        address: Self::Address,
        key: Self::Key,
    ) -> Result<Option<Self::Value>, Self::Error>;
    fn query_info(&mut self, address: Self::Address) -> Result<ContractInfoResponse, Self::Error>;
}
