// loader.rs ---

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

use crate::{
    bank::BankAccountIdOf,
    host::{Host, HostMessageCustomOf},
    input::Input,
};
use cosmwasm_minimal_std::{
    Binary, ContractResult, DeserializeLimit, Event, QueryResult, ReadLimit, Response,
};
use serde::de::DeserializeOwned;

pub type LoaderCodeIdOf<T> = <T as Loader>::CodeId;
pub type LoaderOutputOf<T> = <T as Loader>::Output;
pub type LoaderErrorOf<T> = <T as Loader>::Error;
pub type LoaderInputOf<T> = <T as Loader>::Input;

pub trait Loader: Host {
    type CodeId;
    type Input;
    type Output;
    type Error;
    fn query_continuation(
        &mut self,
        address: BankAccountIdOf<Self>,
        message: &[u8],
    ) -> Result<QueryResult, LoaderErrorOf<Self>>;
    fn execution_continuation<I>(
        &mut self,
        address: BankAccountIdOf<Self>,
        input: Self::Input,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, LoaderErrorOf<Self>>
    where
        I: Input,
        I::Output: DeserializeOwned
            + ReadLimit
            + DeserializeLimit
            + Into<ContractResult<Response<HostMessageCustomOf<Self>>>>;
    fn new(&mut self, code_id: Self::CodeId) -> Result<BankAccountIdOf<Self>, LoaderErrorOf<Self>>;
    fn set_code_id(
        &mut self,
        address: BankAccountIdOf<Self>,
        new_code_id: Self::CodeId,
    ) -> Result<(), LoaderErrorOf<Self>>;
    fn code_id(
        &mut self,
        address: BankAccountIdOf<Self>,
    ) -> Result<Self::CodeId, LoaderErrorOf<Self>>;
}
