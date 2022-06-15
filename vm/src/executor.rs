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

use crate::{
    input::{Input, OutputOf},
    memory::{
        LimitedRead, RawFromRegion, RawIntoRegion, ReadWriteMemory, ReadableMemoryErrorOf,
        WritableMemoryErrorOf, Write,
    },
    tagged::Tagged,
    vm::{VmErrorOf, VmInputOf, VmOutputOf, VM},
};
use alloc::vec::Vec;
use core::{fmt::Debug, marker::PhantomData};
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
impl AsFunctionName for InstantiateInput {
    fn name() -> &'static str {
        "instantiate"
    }
}

pub struct ExecuteInput;
impl Input for ExecuteInput {
    type Output = ExecuteResult;
}
impl AsFunctionName for ExecuteInput {
    fn name() -> &'static str {
        "execute"
    }
}

pub struct ReplyInput;
impl Input for ReplyInput {
    type Output = ReplyResult;
}
impl AsFunctionName for ReplyInput {
    fn name() -> &'static str {
        "reply"
    }
}

pub trait AsFunctionName {
    fn name() -> &'static str;
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
    for<'x> TryFrom<VmOutputOf<'x, T>, Error = VmErrorOf<T>>
    + TryFrom<usize>
    + TryInto<usize>
    + Copy
    + Ord
    + Debug
where
    T: ?Sized + VM,
{
}

pub mod constants {
    /// A kibi (kilo binary)
    pub const KI: u32 = 1024;
    /// A mibi (mega binary)
    pub const MI: u32 = 1024 * 1024;
    /// Max key length for db_write/db_read/db_remove/db_scan (when VM reads the key argument from Wasm
    /// memory)
    pub const MAX_LENGTH_DB_KEY: u32 = 64 * KI;
    /// Max value length for db_write (when VM reads the value argument from Wasm memory)
    pub const MAX_LENGTH_DB_VALUE: u32 = 128 * KI;
    /// Typically 20 (Cosmos SDK, Ethereum), 32 (Nano, Substrate) or 54 (MockApi)
    pub const MAX_LENGTH_CANONICAL_ADDRESS: u32 = 64;
    /// The max length of human address inputs (in bytes).
    /// The maximum allowed size for [bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32)
    /// is 90 characters and we're adding some safety margin around that for other formats.
    pub const MAX_LENGTH_HUMAN_ADDRESS: u32 = 256;
    pub const MAX_LENGTH_QUERY_CHAIN_REQUEST: u32 = 64 * KI;
    /// Length of a serialized Ed25519  signature
    pub const MAX_LENGTH_ED25519_SIGNATURE: u32 = 64;
    /// Max length of a Ed25519 message in bytes.
    /// This is an arbitrary value, for performance / memory contraints. If you need to verify larger
    /// messages, let us know.
    pub const MAX_LENGTH_ED25519_MESSAGE: u32 = 128 * 1024;
    /// Max number of batch Ed25519 messages / signatures / public_keys.
    /// This is an arbitrary value, for performance / memory contraints. If you need to batch-verify a
    /// larger number of signatures, let us know.
    pub const MAX_COUNT_ED25519_BATCH: u32 = 256;

    /// Max length for a debug message
    pub const MAX_LENGTH_DEBUG: u32 = 2 * MI;
}

pub struct ConstantReadLimit<const K: u32>;
impl<const K: u32> ReadLimit for ConstantReadLimit<K> {
    fn read_limit() -> usize {
        K as usize
    }
}

pub type ExecutorPointerOf<T> = <T as Executor>::Pointer;
pub type ExecutorMemoryOf<'a, T> = <T as Executor>::Memory<'a>;

pub trait Executor: VM
where
    for<'x> VmErrorOf<Self>: From<ReadableMemoryErrorOf<Self::Memory<'x>>>
        + From<WritableMemoryErrorOf<Self::Memory<'x>>>
        + From<ExecutorError>,
{
    type Pointer: ExecutorPointer<Self>;
    type Memory<'a>: ReadWriteMemory<Pointer = Self::Pointer>;

    fn memory<'a>(&mut self) -> Self::Memory<'a>;

    fn allocate<L>(&mut self, len: L) -> Result<Self::Pointer, VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>,
        Self::Pointer: TryFrom<L>,
    {
        let len_value =
            Self::Pointer::try_from(len).map_err(|_| ExecutorError::AllocationWouldOverflow)?;
        let result = self.call(AllocateInput(len_value))?;
        log::debug!("Allocate: size={:?}, pointer={:?}", len_value, result);
        Ok(result)
    }

    fn deallocate<L>(&mut self, pointer: L) -> Result<(), VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>:
            TryFrom<DeallocateInput<Self::Pointer>, Error = VmErrorOf<Self>>,
        Self::Pointer: TryFrom<L>,
    {
        log::debug!("Deallocate");
        let pointer_value = Self::Pointer::try_from(pointer)
            .map_err(|_| ExecutorError::DeallocationWouldOverflow)?;
        self.call(DeallocateInput(pointer_value))?;
        Ok(())
    }

    fn passthrough_in<V>(
        &mut self,
        data: &[u8],
    ) -> Result<Tagged<Self::Pointer, V>, VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>,
    {
        log::debug!("PassthroughIn");
        let pointer = self.allocate::<usize>(data.len())?;
        let memory = &self.memory();
        RawIntoRegion::try_from(Write(memory, pointer, data))?;
        Ok(Tagged::new(pointer))
    }

    fn passthrough_out<V>(&mut self, pointer: Self::Pointer) -> Result<Vec<u8>, VmErrorOf<Self>>
    where
        V: ReadLimit,
    {
        log::debug!("PassthroughOut");
        let memory = &self.memory();
        let RawFromRegion(buffer) = RawFromRegion::try_from(LimitedRead(
            memory,
            pointer,
            Self::Pointer::try_from(V::read_limit())
                .map_err(|_| ExecutorError::CallReadLimitWouldOverflow)?,
        ))?;
        Ok(buffer)
    }

    fn marshall_in<V>(&mut self, x: &V) -> Result<Tagged<Self::Pointer, V>, VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>,
        V: serde::ser::Serialize + Sized,
    {
        log::debug!("MarshallIn");
        let serialized = serde_json::to_vec(x).map_err(|_| ExecutorError::FailedToSerialize)?;
        Ok(self.passthrough_in(&serialized)?)
    }

    fn marshall_out<V>(&mut self, pointer: Self::Pointer) -> Result<V, VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>,
        V: serde::de::DeserializeOwned + ReadLimit + DeserializeLimit,
    {
        log::debug!("MarshallOut");
        let memory = &self.memory();
        let RawFromRegion(output) = RawFromRegion::try_from(LimitedRead(
            memory,
            pointer,
            Self::Pointer::try_from(V::read_limit())
                .map_err(|_| ExecutorError::CallReadLimitWouldOverflow)?,
        ))?;
        Ok(serde_json::from_slice(&output).map_err(|_| ExecutorError::FailedToDeserialize)?)
    }

    fn cosmwasm_call<I>(
        &mut self,
        env: Env,
        info: MessageInfo,
        message: &[u8],
    ) -> Result<I::Output, VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>
            + TryFrom<CosmwasmCallInput<'x, Self::Pointer, I>, Error = VmErrorOf<Self>>,
        I: Input,
        I::Output: DeserializeOwned + ReadLimit + DeserializeLimit,
    {
        log::debug!("Call");
        let input = CosmwasmCallInput(
            self.marshall_in(&env)?,
            self.marshall_in(&info)?,
            self.passthrough_in(message)?,
            PhantomData,
        );
        let pointer = self.call(input)?;
        self.marshall_out(pointer)
    }

    fn cosmwasm_query(&mut self, env: Env, message: &[u8]) -> Result<QueryResult, VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>
            + TryFrom<CosmwasmQueryInput<'x, Self::Pointer>, Error = VmErrorOf<Self>>,
    {
        log::debug!("Query");
        let input = CosmwasmQueryInput(self.marshall_in(&env)?, self.passthrough_in(message)?);
        let pointer = self.call(input)?;
        self.marshall_out(pointer)
    }
}
