// executor.rs ---

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

use core::{fmt::Debug, marker::PhantomData};

use crate::{
    input::{Input, OutputOf},
    memory::{
        LimitedRead, Pointable, RawFromRegion, RawIntoRegion, ReadWriteMemory, ReadableMemory,
        WritableMemory, Write,
    },
    tagged::Tagged,
    vm::{Module, VM},
};
use cosmwasm_minimal_std::{
    DeserializeLimit, Env, ExecuteResult, InstantiateResult, MessageInfo, QueryResult, ReadLimit,
    ReplyResult,
};
use serde::de::DeserializeOwned;
use wasmi::RuntimeValue;

pub trait Environment {
    type Query: Input;
    type Error;
    fn query(query: Self::Query) -> Result<OutputOf<Self::Query>, Self::Error>;
}

type ErrorOf<T> = <T as VM>::Error;
type ModuleOf<T> = <T as VM>::Module;
type ModuleMemoryOf<T> = <ModuleOf<T> as Module>::Memory;
type ModuleErrorOf<T> = <ModuleOf<T> as Module>::Error;
type ModuleInputOf<'a, T> = <ModuleOf<T> as Module>::Input<'a>;
type ModuleOutputOf<'a, T> = <ModuleOf<T> as Module>::Output<'a>;

pub struct AllocateInput<Pointer>(pub Pointer);
impl<Pointer> Input for AllocateInput<Pointer> {
    type Output = Pointer;
}

pub struct DeallocateInput<Pointer>(pub Pointer);
impl<Pointer> Input for DeallocateInput<Pointer> {
    type Output = Pointer;
}

pub struct CosmwasmQueryInput<'a, Pointer>(pub Tagged<Pointer, Env>, pub Tagged<Pointer, &'a [u8]>);
impl<'a, Pointer> Input for CosmwasmQueryInput<'a, Pointer> {
    type Output = Pointer;
}

pub struct CosmwasmCallInput<'a, Pointer, I>(
    pub Tagged<Pointer, Env>,
    pub Tagged<Pointer, MessageInfo>,
    pub Tagged<Pointer, &'a [u8]>,
    pub PhantomData<I>,
);
impl<'a, Pointer, I: Input> Input for CosmwasmCallInput<'a, Pointer, I> {
    type Output = Pointer;
}

pub struct InstantiateInput;
impl Input for InstantiateInput {
    type Output = InstantiateResult;
}

pub struct ExecuteInput;
impl Input for ExecuteInput {
    type Output = ExecuteResult;
}

pub struct ReplyInput;
impl Input for ReplyInput {
    type Output = ReplyResult;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SimpleExecutorError {
    FailedToSerialize,
    FailedToDeserialize,
    ValueWouldOverflowPointer,
}

pub struct AsSimpleExecutor<T> {
    pub vm: T,
}
impl<T, Pointer> AsSimpleExecutor<T>
where
    T: VM,
    Pointer: for<'x> TryFrom<ModuleOutputOf<'x, T>, Error = ModuleErrorOf<T>>
        + TryFrom<usize>
        + TryInto<usize>
        + Copy
        + Ord
        + Debug,
    for<'x> ModuleOutputOf<'x, T>:
        Pointable<Pointer = Pointer> + TryInto<RuntimeValue, Error = ModuleErrorOf<T>>,
    ErrorOf<T>: From<SimpleExecutorError>,
{
    pub fn allocate<L>(&mut self, module: &ModuleOf<T>, len: L) -> Result<Pointer, ErrorOf<T>>
    where
        for<'x> ModuleInputOf<'x, T>: TryFrom<AllocateInput<Pointer>, Error = ErrorOf<T>>,
        Pointer: TryFrom<L>,
    {
        let len_value =
            Pointer::try_from(len).map_err(|_| SimpleExecutorError::ValueWouldOverflowPointer)?;
        let input = AllocateInput(len_value);
        let result = self
            .vm
            .call::<AllocateInput<Pointer>, _, _>(module, input)?;
        log::debug!("Allocate: size={:?}, ptr={:?}", len_value, result);
        Ok(result)
    }

    pub fn deallocate<L>(&mut self, module: &ModuleOf<T>, ptr: L) -> Result<(), ErrorOf<T>>
    where
        for<'x> ModuleInputOf<'x, T>: TryFrom<DeallocateInput<Pointer>, Error = ErrorOf<T>>,
        Pointer: TryFrom<L>,
    {
        log::debug!("Deallocate");
        let ptr_value =
            Pointer::try_from(ptr).map_err(|_| SimpleExecutorError::ValueWouldOverflowPointer)?;
        let input = DeallocateInput(ptr_value);
        self.vm
            .call::<DeallocateInput<Pointer>, _, _>(module, input)?;
        Ok(())
    }

    pub fn passthrough_in<V>(
        &mut self,
        module: &ModuleOf<T>,
        data: &[u8],
    ) -> Result<Tagged<Pointer, V>, ErrorOf<T>>
    where
        for<'x> ModuleInputOf<'x, T>: TryFrom<AllocateInput<Pointer>, Error = ErrorOf<T>>,
        ModuleMemoryOf<T>: ReadWriteMemory<Pointer = Pointer>,
        ErrorOf<T>: From<<ModuleMemoryOf<T> as WritableMemory>::Error>
            + From<<ModuleMemoryOf<T> as ReadableMemory>::Error>
            + From<SimpleExecutorError>,
    {
        log::debug!("PassthroughIn");
        let ptr = self.allocate::<usize>(module, data.len())?;
        let memory = module.memory();
        match TryFrom::try_from(Write(memory, ptr, data)) {
            Ok(RawIntoRegion) => Ok(Tagged::new(ptr)),
            Err(e) => Err(e.into()),
        }
    }

    pub fn marshall_in<V>(
        &mut self,
        module: &ModuleOf<T>,
        x: &V,
    ) -> Result<Tagged<Pointer, V>, ErrorOf<T>>
    where
        for<'x> ModuleInputOf<'x, T>: TryFrom<AllocateInput<Pointer>, Error = ErrorOf<T>>,
        ModuleMemoryOf<T>: ReadWriteMemory<Pointer = Pointer>,
        ErrorOf<T>: From<<ModuleMemoryOf<T> as WritableMemory>::Error>
            + From<<ModuleMemoryOf<T> as ReadableMemory>::Error>
            + From<SimpleExecutorError>,
        V: serde::ser::Serialize + Sized,
    {
        log::debug!("MarshallIn");
        let serialized =
            serde_json::to_vec(x).map_err(|_| SimpleExecutorError::FailedToSerialize)?;
        Ok(self.passthrough_in(module, &serialized)?)
    }

    pub fn cosmwasm_call<I>(
        &mut self,
        module: &ModuleOf<T>,
        env: Env,
        info: MessageInfo,
        message: &[u8],
    ) -> Result<I::Output, ErrorOf<T>>
    where
        for<'x> ModuleInputOf<'x, T>: TryFrom<AllocateInput<Pointer>, Error = ErrorOf<T>>
            + TryFrom<CosmwasmCallInput<'x, Pointer, I>, Error = ErrorOf<T>>,
        ModuleMemoryOf<T>: ReadWriteMemory<Pointer = Pointer>,
        ErrorOf<T>: From<<ModuleMemoryOf<T> as WritableMemory>::Error>
            + From<<ModuleMemoryOf<T> as ReadableMemory>::Error>
            + From<SimpleExecutorError>,
        I: Input,
        I::Output: DeserializeOwned + ReadLimit + DeserializeLimit,
    {
        log::debug!("Call");
        let input = CosmwasmCallInput(
            self.marshall_in(module, &env)?,
            self.marshall_in(module, &info)?,
            self.passthrough_in(module, message)?,
            PhantomData,
        );
        let pointer = self
            .vm
            .call::<CosmwasmCallInput<Pointer, I>, _, _>(module, input)?;
        let memory = module.memory();
        let RawFromRegion(output) = RawFromRegion::try_from(LimitedRead(
            memory,
            pointer,
            Pointer::try_from(<I::Output as ReadLimit>::read_limit())
                .map_err(|_| SimpleExecutorError::ValueWouldOverflowPointer)?,
        ))?;
        Ok(serde_json::from_slice(&output).map_err(|_| SimpleExecutorError::FailedToSerialize)?)
    }

    pub fn cosmwasm_query(
        &mut self,
        module: &ModuleOf<T>,
        env: Env,
        message: &[u8],
    ) -> Result<QueryResult, ErrorOf<T>>
    where
        for<'x> ModuleInputOf<'x, T>: TryFrom<AllocateInput<Pointer>, Error = ErrorOf<T>>
            + TryFrom<CosmwasmQueryInput<'x, Pointer>, Error = ErrorOf<T>>,
        ModuleMemoryOf<T>: ReadWriteMemory<Pointer = Pointer>,
        ErrorOf<T>: From<<ModuleMemoryOf<T> as WritableMemory>::Error>
            + From<<ModuleMemoryOf<T> as ReadableMemory>::Error>
            + From<SimpleExecutorError>,
    {
        log::debug!("Query");
        let input = CosmwasmQueryInput(
            self.marshall_in(module, &env)?,
            self.passthrough_in(module, message)?,
        );
        let pointer = self
            .vm
            .call::<CosmwasmQueryInput<Pointer>, _, _>(module, input)?;
        let memory = module.memory();
        let RawFromRegion(output) = RawFromRegion::try_from(LimitedRead(
            memory,
            pointer,
            Pointer::try_from(QueryResult::read_limit())
                .map_err(|_| SimpleExecutorError::ValueWouldOverflowPointer)?,
        ))?;
        Ok(serde_json::from_slice(&output).map_err(|_| SimpleExecutorError::FailedToSerialize)?)
    }
}
