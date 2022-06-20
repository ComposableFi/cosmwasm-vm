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
    has::Has,
    input::{Input, OutputOf},
    memory::{
        LimitedRead, RawFromRegion, RawIntoRegion, ReadWriteMemory, ReadableMemory,
        ReadableMemoryErrorOf, WritableMemoryErrorOf, Write,
    },
    tagged::Tagged,
    vm::{VmErrorOf, VmInputOf, VmOutputOf, VM},
};
use alloc::vec::Vec;
use core::{fmt::Debug, marker::PhantomData};
use cosmwasm_minimal_std::{
    DeserializeLimit, Empty, Env, ExecuteResult, InstantiateResult, MessageInfo, MigrateResult,
    QueryResult, ReadLimit, ReplyResult,
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
impl<Pointer> AsFunctionName for AllocateInput<Pointer> {
    fn name() -> &'static str {
        "allocate"
    }
}

pub struct Unit;
pub struct DeallocateInput<Pointer>(pub Pointer);
impl<Pointer> Input for DeallocateInput<Pointer> {
    type Output = Unit;
}
impl<Pointer> AsFunctionName for DeallocateInput<Pointer> {
    fn name() -> &'static str {
        "deallocate"
    }
}

pub struct CosmwasmQueryInput<'a, Pointer>(pub Tagged<Pointer, Env>, pub Tagged<Pointer, &'a [u8]>);
impl<'a, Pointer> Input for CosmwasmQueryInput<'a, Pointer> {
    type Output = Pointer;
}
impl<'a, Pointer> AsFunctionName for CosmwasmQueryInput<'a, Pointer> {
    fn name() -> &'static str {
        "query"
    }
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

pub struct InstantiateInput<T = Empty>(PhantomData<T>);
impl<T> Input for InstantiateInput<T> {
    type Output = InstantiateResult<T>;
}
impl<T> AsFunctionName for InstantiateInput<T> {
    fn name() -> &'static str {
        "instantiate"
    }
}

pub struct ExecuteInput<T = Empty>(PhantomData<T>);
impl<T> Input for ExecuteInput<T> {
    type Output = ExecuteResult<T>;
}
impl<T> AsFunctionName for ExecuteInput<T> {
    fn name() -> &'static str {
        "execute"
    }
}

pub struct ReplyInput<T = Empty>(PhantomData<T>);
impl<T> Input for ReplyInput<T> {
    type Output = ReplyResult<T>;
}
impl<T> AsFunctionName for ReplyInput<T> {
    fn name() -> &'static str {
        "reply"
    }
}

pub struct MigrateInput<T = Empty>(PhantomData<T>);
impl<T> Input for MigrateInput<T> {
    type Output = MigrateResult<T>;
}
impl<T> AsFunctionName for MigrateInput<T> {
    fn name() -> &'static str {
        "migrate"
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

pub mod constants {
    /// A kibi (kilo binary)
    pub const KI: usize = 1024;
    /// A mibi (mega binary)
    pub const MI: usize = 1024 * 1024;
    /// Max key length for db_write/db_read/db_remove/db_scan (when VM reads the key argument from Wasm
    /// memory)
    pub const MAX_LENGTH_DB_KEY: usize = 64 * KI;
    /// Max value length for db_write (when VM reads the value argument from Wasm memory)
    pub const MAX_LENGTH_DB_VALUE: usize = 128 * KI;
    /// Typically 20 (Cosmos SDK, Ethereum), 32 (Nano, Substrate) or 54 (MockApi)
    pub const MAX_LENGTH_CANONICAL_ADDRESS: usize = 64;
    /// The max length of human address inputs (in bytes).
    /// The maximum allowed size for [bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32)
    /// is 90 characters and we're adding some safety margin around that for other formats.
    pub const MAX_LENGTH_HUMAN_ADDRESS: usize = 256;
    pub const MAX_LENGTH_QUERY_CHAIN_REQUEST: usize = 64 * KI;
    /// Length of a serialized Ed25519  signature
    pub const MAX_LENGTH_ED25519_SIGNATURE: usize = 64;
    /// Max length of a Ed25519 message in bytes.
    /// This is an arbitrary value, for performance / memory contraints. If you need to verify larger
    /// messages, let us know.
    pub const MAX_LENGTH_ED25519_MESSAGE: usize = 128 * 1024;
    /// Max number of batch Ed25519 messages / signatures / public_keys.
    /// This is an arbitrary value, for performance / memory contraints. If you need to batch-verify a
    /// larger number of signatures, let us know.
    pub const MAX_COUNT_ED25519_BATCH: usize = 256;

    /// Max length for a debug message
    pub const MAX_LENGTH_DEBUG: usize = 2 * MI;

    /// Max length for an abort message
    pub const MAX_LENGTH_ABORT: usize = 2 * MI;
}

pub struct ConstantReadLimit<const K: usize>;
impl<const K: usize> ReadLimit for ConstantReadLimit<K> {
    fn read_limit() -> usize {
        K
    }
}

pub fn allocate<V, P, L>(vm: &mut V, len: L) -> Result<P, VmErrorOf<V>>
where
    V: VM,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<P>, Error = VmErrorOf<V>>,
    P: Copy + TryFrom<L> + Debug + for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>: From<ExecutorError>,
{
    let len_value = P::try_from(len).map_err(|_| ExecutorError::AllocationWouldOverflow)?;
    let result = vm.call(AllocateInput(len_value))?;
    log::trace!("Allocate: size={:?}, pointer={:?}", len_value, result);
    Ok(result)
}

pub fn deallocate<V, P, L>(vm: &mut V, pointer: L) -> Result<(), VmErrorOf<V>>
where
    V: VM,
    for<'x> Unit: TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> VmInputOf<'x, V>: TryFrom<DeallocateInput<P>, Error = VmErrorOf<V>>,
    P: Copy + TryFrom<L> + Debug + for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>: From<ExecutorError>,
{
    log::trace!("Deallocate");
    let pointer_value =
        P::try_from(pointer).map_err(|_| ExecutorError::DeallocationWouldOverflow)?;
    vm.call(DeallocateInput(pointer_value))?;
    Ok(())
}

pub fn passthrough_in<V, T>(vm: &mut V, data: &[u8]) -> Result<Tagged<V::Pointer, T>, VmErrorOf<V>>
where
    V: VM + ReadWriteMemory,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<V::Pointer>, Error = VmErrorOf<V>>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>:
        From<ReadableMemoryErrorOf<V>> + From<WritableMemoryErrorOf<V>> + From<ExecutorError>,
{
    log::trace!("PassthroughIn");
    let pointer = allocate::<_, _, usize>(vm, data.len())?;
    RawIntoRegion::try_from(Write(vm, pointer, data))?;
    Ok(Tagged::new(pointer))
}

pub fn passthrough_out<V, T>(vm: &V, pointer: V::Pointer) -> Result<Vec<u8>, VmErrorOf<V>>
where
    V: VM + ReadableMemory,
    T: ReadLimit,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<V::Pointer>, Error = VmErrorOf<V>>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>: From<ReadableMemoryErrorOf<V>> + From<ExecutorError>,
{
    log::trace!("PassthroughOut");
    let RawFromRegion(buffer) = RawFromRegion::try_from(LimitedRead(
        vm,
        pointer,
        TryFrom::<usize>::try_from(T::read_limit())
            .map_err(|_| ExecutorError::CallReadLimitWouldOverflow)?,
    ))?;
    Ok(buffer)
}

pub fn marshall_in<V, T>(vm: &mut V, x: &T) -> Result<Tagged<V::Pointer, T>, VmErrorOf<V>>
where
    V: VM + ReadWriteMemory,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<V::Pointer>, Error = VmErrorOf<V>>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>:
        From<ReadableMemoryErrorOf<V>> + From<WritableMemoryErrorOf<V>> + From<ExecutorError>,
    T: serde::ser::Serialize + Sized,
{
    log::trace!("MarshallIn");
    let serialized = serde_json::to_vec(x).map_err(|_| ExecutorError::FailedToSerialize)?;
    Ok(passthrough_in(vm, &serialized)?)
}

pub fn marshall_out<V, T>(vm: &V, pointer: V::Pointer) -> Result<T, VmErrorOf<V>>
where
    V: VM + ReadableMemory,
    T: ReadLimit,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<V::Pointer>, Error = VmErrorOf<V>>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>: From<ReadableMemoryErrorOf<V>> + From<ExecutorError>,
    T: serde::de::DeserializeOwned + ReadLimit + DeserializeLimit,
{
    log::trace!("MarshallOut");
    let RawFromRegion(output) = RawFromRegion::try_from(LimitedRead(
        vm,
        pointer,
        TryFrom::<usize>::try_from(T::read_limit())
            .map_err(|_| ExecutorError::CallReadLimitWouldOverflow)?,
    ))?;
    Ok(serde_json::from_slice(&output).map_err(|_| ExecutorError::FailedToDeserialize)?)
}

pub fn cosmwasm_call<I, V>(vm: &mut V, message: &[u8]) -> Result<I::Output, VmErrorOf<V>>
where
    V: VM + ReadWriteMemory + Has<Env> + Has<MessageInfo>,
    I: Input,
    I::Output: DeserializeOwned + ReadLimit + DeserializeLimit,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmCallInput<'x, V::Pointer, I>, Error = VmErrorOf<V>>,
    VmErrorOf<V>:
        From<ReadableMemoryErrorOf<V>> + From<WritableMemoryErrorOf<V>> + From<ExecutorError>,
{
    log::trace!("Call");
    let env = vm.get();
    let info = vm.get();
    let input = CosmwasmCallInput(
        marshall_in(vm, &env)?,
        marshall_in(vm, &info)?,
        passthrough_in(vm, message)?,
        PhantomData,
    );
    let pointer = vm.call(input)?;
    marshall_out(vm, pointer)
}

pub fn cosmwasm_query<V>(vm: &mut V, message: &[u8]) -> Result<QueryResult, VmErrorOf<V>>
where
    V: VM + ReadWriteMemory + Has<Env>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmQueryInput<'x, V::Pointer>, Error = VmErrorOf<V>>,
    VmErrorOf<V>: From<ReadableMemoryErrorOf<V>> + From<ExecutorError>,
{
    log::trace!("Query");
    let env = vm.get();
    let input = CosmwasmQueryInput(marshall_in(vm, &env)?, passthrough_in(vm, message)?);
    let pointer = vm.call(input)?;
    marshall_out(vm, pointer)
}
