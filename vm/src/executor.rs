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
        LimitedRead, RawFromRegion, RawIntoRegion, ReadWriteMemory, ReadableMemory,
        WritableMemory, Write,
    },
    tagged::Tagged,
    vm::{Module, VM, VmErrorOf},
};
use cosmwasm_minimal_std::{
    DeserializeLimit, Env, ExecuteResult, InstantiateResult, MessageInfo, QueryResult, ReadLimit,
    ReplyResult,
};
use serde::de::DeserializeOwned;

pub trait Environment {
    type Query: Input;
    type Error;
    fn query(query: Self::Query) -> Result<OutputOf<Self::Query>, Self::Error>;
}

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
pub enum ExecutorError {
    FailedToSerialize,
    FailedToDeserialize,
    AllocationWouldOverflow,
    DeallocationWouldOverflow,
    QueryReadLimitWouldOverflow,
    CallReadLimitWouldOverflow,
}

pub trait ExecutorPointer<T>:
    for<'x> TryFrom<ModuleOutputOf<'x, T>, Error = ModuleErrorOf<T>>
    + TryFrom<usize>
    + TryInto<usize>
    + Copy
    + Ord
    + Debug
where
    T: ?Sized + VM,
{
}

pub trait Executor: VM
where
    VmErrorOf<Self>: From<ExecutorError>,
{
    type Pointer: ExecutorPointer<Self>;

    fn allocate<L>(&mut self, module: &ModuleOf<Self>, len: L) -> Result<Self::Pointer, VmErrorOf<Self>>
    where
        for<'x> ModuleInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>,
        Self::Pointer: TryFrom<L>,
    {
        let len_value =
            Self::Pointer::try_from(len).map_err(|_| ExecutorError::AllocationWouldOverflow)?;
        let input = AllocateInput(len_value);
        let result = self.call::<AllocateInput<Self::Pointer>, _, _>(module, input)?;
        log::debug!("Allocate: size={:?}, ptr={:?}", len_value, result);
        Ok(result)
    }

    fn deallocate<L>(&mut self, module: &ModuleOf<Self>, ptr: L) -> Result<(), VmErrorOf<Self>>
    where
        for<'x> ModuleInputOf<'x, Self>: TryFrom<DeallocateInput<Self::Pointer>, Error = VmErrorOf<Self>>,
        Self::Pointer: TryFrom<L>,
    {
        log::debug!("Deallocate");
        let ptr_value =
            Self::Pointer::try_from(ptr).map_err(|_| ExecutorError::DeallocationWouldOverflow)?;
        let input = DeallocateInput(ptr_value);
        self.call::<DeallocateInput<Self::Pointer>, _, _>(module, input)?;
        Ok(())
    }

    fn passthrough_in<V>(
        &mut self,
        module: &ModuleOf<Self>,
        data: &[u8],
    ) -> Result<Tagged<Self::Pointer, V>, VmErrorOf<Self>>
    where
        for<'x> ModuleInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>,
        ModuleMemoryOf<Self>: ReadWriteMemory<Pointer = Self::Pointer>,
        VmErrorOf<Self>: From<<ModuleMemoryOf<Self> as WritableMemory>::Error>
            + From<<ModuleMemoryOf<Self> as ReadableMemory>::Error>
            + From<ExecutorError>,
    {
        log::debug!("PassthroughIn");
        let ptr = self.allocate::<usize>(module, data.len())?;
        let memory = module.memory();
        RawIntoRegion::try_from(Write(memory, ptr, data))?;
        Ok(Tagged::new(ptr))
    }

    fn marshall_in<V>(
        &mut self,
        module: &ModuleOf<Self>,
        x: &V,
    ) -> Result<Tagged<Self::Pointer, V>, VmErrorOf<Self>>
    where
        for<'x> ModuleInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>,
        ModuleMemoryOf<Self>: ReadWriteMemory<Pointer = Self::Pointer>,
        VmErrorOf<Self>: From<<ModuleMemoryOf<Self> as WritableMemory>::Error>
            + From<<ModuleMemoryOf<Self> as ReadableMemory>::Error>
            + From<ExecutorError>,
        V: serde::ser::Serialize + Sized,
    {
        log::debug!("MarshallIn");
        let serialized = serde_json::to_vec(x).map_err(|_| ExecutorError::FailedToSerialize)?;
        Ok(self.passthrough_in(module, &serialized)?)
    }

    fn cosmwasm_call<I>(
        &mut self,
        module: &ModuleOf<Self>,
        env: Env,
        info: MessageInfo,
        message: &[u8],
    ) -> Result<I::Output, VmErrorOf<Self>>
    where
        for<'x> ModuleInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>
            + TryFrom<CosmwasmCallInput<'x, Self::Pointer, I>, Error = VmErrorOf<Self>>,
        ModuleMemoryOf<Self>: ReadWriteMemory<Pointer = Self::Pointer>,
        VmErrorOf<Self>: From<<ModuleMemoryOf<Self> as WritableMemory>::Error>
            + From<<ModuleMemoryOf<Self> as ReadableMemory>::Error>
            + From<ExecutorError>,
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
        let pointer = self.call::<CosmwasmCallInput<Self::Pointer, I>, _, _>(module, input)?;
        let memory = module.memory();
        let RawFromRegion(output) = RawFromRegion::try_from(LimitedRead(
            memory,
            pointer,
            Self::Pointer::try_from(<I::Output as ReadLimit>::read_limit())
                .map_err(|_| ExecutorError::CallReadLimitWouldOverflow)?,
        ))?;
        Ok(serde_json::from_slice(&output).map_err(|_| ExecutorError::FailedToDeserialize)?)
    }

    fn cosmwasm_query(
        &mut self,
        module: &ModuleOf<Self>,
        env: Env,
        message: &[u8],
    ) -> Result<QueryResult, VmErrorOf<Self>>
    where
        for<'x> ModuleInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>
            + TryFrom<CosmwasmQueryInput<'x, Self::Pointer>, Error = VmErrorOf<Self>>,
        ModuleMemoryOf<Self>: ReadWriteMemory<Pointer = Self::Pointer>,
        VmErrorOf<Self>: From<<ModuleMemoryOf<Self> as WritableMemory>::Error>
            + From<<ModuleMemoryOf<Self> as ReadableMemory>::Error>
            + From<ExecutorError>,
    {
        log::debug!("Query");
        let input = CosmwasmQueryInput(
            self.marshall_in(module, &env)?,
            self.passthrough_in(module, message)?,
        );
        let pointer = self.call::<CosmwasmQueryInput<Self::Pointer>, _, _>(module, input)?;
        let memory = module.memory();
        let RawFromRegion(output) = RawFromRegion::try_from(LimitedRead(
            memory,
            pointer,
            Self::Pointer::try_from(QueryResult::read_limit())
                .map_err(|_| ExecutorError::QueryReadLimitWouldOverflow)?,
        ))?;
        Ok(serde_json::from_slice(&output).map_err(|_| ExecutorError::FailedToDeserialize)?)
    }
}
