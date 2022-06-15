// actor_system.rs ---

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
    executor::{AllocateInput, CosmwasmCallInput, Executor, ExecutorError, ExecutorMemoryOf},
    input::Input,
    loader::{Loader, LoaderCodeIdOf, LoaderErrorOf},
    memory::{ReadableMemoryErrorOf, WritableMemoryErrorOf},
    transaction::{Transactional, TransactionalErrorOf},
    vm::{VmErrorOf, VmInputOf},
};
use cosmwasm_minimal_std::{DeserializeLimit, Env, MessageInfo, ReadLimit};
use serde::de::DeserializeOwned;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SystemError {}

pub trait System: Executor + Transactional + Loader + Sized
where
    for<'x> VmErrorOf<Self>: From<ReadableMemoryErrorOf<ExecutorMemoryOf<'x, Self>>>
        + From<WritableMemoryErrorOf<ExecutorMemoryOf<'x, Self>>>
        + From<ExecutorError>
        + From<SystemError>
        + From<TransactionalErrorOf<Self>>
        + From<LoaderErrorOf<Self>>,
    for<'x> u64: From<LoaderCodeIdOf<Self>>,
{
    fn cosmwasm_orchestrate<I>(
        &mut self,
        _: Env,
        _: MessageInfo,
        _: &[u8],
    ) -> Result<I::Output, VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>
            + TryFrom<CosmwasmCallInput<'x, Self::Pointer, I>, Error = VmErrorOf<Self>>,
        I: Input,
        I::Output: DeserializeOwned + ReadLimit + DeserializeLimit,
    {
        todo!()
    }
}
