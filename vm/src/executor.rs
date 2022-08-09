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
    input::Input,
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

/// The type representing a call to a contract `allocate` export.
pub struct AllocateInput<Pointer>(pub Pointer);
impl<Pointer> Input for AllocateInput<Pointer> {
    type Output = Pointer;
}
impl<Pointer> AsFunctionName for AllocateInput<Pointer> {
    const NAME: &'static str = "allocate";
}

pub struct Unit;

/// The type representing a call to a contract `deallocate` export.
pub struct DeallocateInput<Pointer>(pub Pointer);
impl<Pointer> Input for DeallocateInput<Pointer> {
    type Output = Unit;
}
impl<Pointer> AsFunctionName for DeallocateInput<Pointer> {
    const NAME: &'static str = "deallocate";
}

/// The type representing a call to a contract `query` export.
pub struct QueryInput;
impl Input for QueryInput {
    type Output = QueryResult;
}
impl AsFunctionName for QueryInput {
    const NAME: &'static str = "query";
}
impl HasInfo for QueryInput {
    const HAS_INFO: bool = false;
}

/// The type representing a call to a contract `instantiate` export.
pub struct InstantiateInput<T = Empty>(PhantomData<T>);
impl<T> Input for InstantiateInput<T> {
    type Output = InstantiateResult<T>;
}
impl<T> AsFunctionName for InstantiateInput<T> {
    const NAME: &'static str = "instantiate";
}
impl<T> HasInfo for InstantiateInput<T> {
    const HAS_INFO: bool = true;
}

/// The type representing a call to a contract `execute` export.
pub struct ExecuteInput<T = Empty>(PhantomData<T>);
impl<T> Input for ExecuteInput<T> {
    type Output = ExecuteResult<T>;
}
impl<T> AsFunctionName for ExecuteInput<T> {
    const NAME: &'static str = "execute";
}
impl<T> HasInfo for ExecuteInput<T> {
    const HAS_INFO: bool = true;
}

/// The type representing a call to a contract `reply` export.
pub struct ReplyInput<T = Empty>(PhantomData<T>);
impl<T> Input for ReplyInput<T> {
    type Output = ReplyResult<T>;
}
impl<T> AsFunctionName for ReplyInput<T> {
    const NAME: &'static str = "reply";
}
impl<T> HasInfo for ReplyInput<T> {
    const HAS_INFO: bool = false;
}

/// The type representing a call to a contract `migrate` export.
pub struct MigrateInput<T = Empty>(PhantomData<T>);
impl<T> Input for MigrateInput<T> {
    type Output = MigrateResult<T>;
}
impl<T> AsFunctionName for MigrateInput<T> {
    const NAME: &'static str = "migrate";
}
impl<T> HasInfo for MigrateInput<T> {
    const HAS_INFO: bool = false;
}

pub trait AsFunctionName {
    const NAME: &'static str;
}

/// Structure that hold the function inputs for `f(env, messageInfo, msg) -> X`.
pub struct CosmwasmCallInput<'a, Pointer, I>(
    pub Tagged<Pointer, Env>,
    pub Tagged<Pointer, MessageInfo>,
    pub Tagged<Pointer, &'a [u8]>,
    pub PhantomData<I>,
);
impl<'a, Pointer, I: Input> Input for CosmwasmCallInput<'a, Pointer, I> {
    type Output = Pointer;
}

/// Structure that hold the function inputs for `f(env, msg) -> X`.
pub struct CosmwasmCallWithoutInfoInput<'a, Pointer, I>(
    pub Tagged<Pointer, Env>,
    pub Tagged<Pointer, &'a [u8]>,
    pub PhantomData<I>,
);
impl<'a, Pointer, I: Input> Input for CosmwasmCallWithoutInfoInput<'a, Pointer, I> {
    type Output = Pointer;
}

/// Whether an input type require the `MessageInfo` message to be passed.
pub trait HasInfo {
    const HAS_INFO: bool;
}

/// Errors likely to happen while doing low level executor calls.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ExecutorError {
    /// Unable to serialize the structure to JSON.
    FailedToSerialize,
    /// Unable to deserialize the JSON payload to the given type.
    FailedToDeserialize,
    /// The requested allocation size is too big and would overflow the memory.
    AllocationWouldOverflow,
    /// The requrested deallocation size is too big and would overflow the memory (must be impossible).
    DeallocationWouldOverflow,
    /// The read limit is too big and could not be converted to a pointer.
    CallReadLimitWouldOverflow,
    /// Pointer is invalid
    InvalidPointer,
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

/// Allow for untyped marshalling to specify a limit while extracting the bytes from a contract memory.
pub struct ConstantReadLimit<const K: usize>;
impl<const K: usize> ReadLimit for ConstantReadLimit<K> {
    fn read_limit() -> usize {
        K
    }
}

/// Allocate a chunk of bytes from the contract memory.
///
/// # Arguments
///
/// * `vm` - the virtual machine.
/// * `len` - the len of the chunk to allocate.
///
/// Returns the chunk pointer.
///
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

/// Deallocate a previously allocated chunk from a contract memory.
///
/// # Arguments
///
/// * `vm` - the virtual machine.
/// * `pointer` - the pointer pointing the memory we will deallocate.
///
///
pub fn deallocate<V>(vm: &mut V, pointer: V::Pointer) -> Result<(), VmErrorOf<V>>
where
    V: VM + ReadWriteMemory,
    for<'x> Unit: TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> VmInputOf<'x, V>: TryFrom<DeallocateInput<V::Pointer>, Error = VmErrorOf<V>>,
    VmErrorOf<V>: From<ExecutorError>,
{
    log::trace!("Deallocate");
    vm.call(DeallocateInput(pointer))?;
    Ok(())
}

/// Allocate memory in the contract and write raw bytes representing some value of type `T`.
///
/// # Arguments
///
/// * `vm` - the virtual machine.
/// * `data` - the raw bytes that will be written in the contract memory.
///
/// Returns either the tagged pointer or a `VmErrorOf<V>`.
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

/// Extract the bytes held by the region identified with the `pointer`.
///
/// # Arguments
///
/// * `vm` - the virtual machine.
/// * `pointer` - the region pointer from which we will read the bytes.
///
/// Returns either the bytes read or a `VmErrorOf<V>`.
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

/// Allocate memory in the contract and write the type `T` serialized in JSON at the newly allocated space.
///
/// # Arguments
///
/// * `vm` - the virtual machine.
/// * `x` - the value the will be serialized to JSON and written in the contract memory.
///
/// Returns either the tagged (type T) pointer to the allocated region or a `VmErrorOf<V>`.
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
    passthrough_in(vm, &serialized)
}

/// Read a JSON serialized value of type `T` from a region identified by the `pointer`.
///
/// # Arguments
///
/// * `vm` - the virtual machine.
/// * `pointer` - the region pointer from which we will read and deserialized a JSON payload of type `T`.
///
/// Returns either the value `T` or a `VmErrorOf<V>`.
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

/// Execute a generic contract export (`instantiate`, `execute`, `migrate` etc...), providing the custom raw `message` input.
///
/// # Arguments
///
/// * `vm` - the virtual machine.
/// * `message` - the contract message passed to the export, usually specific to the contract (InstantiateMsg, ExecuteMsg etc...).
///
/// Returns either the associated `I::Output` or a `VmErrorOf<V>`.
pub fn cosmwasm_call<I, V>(vm: &mut V, message: &[u8]) -> Result<I::Output, VmErrorOf<V>>
where
    V: VM + ReadWriteMemory + Has<Env> + Has<MessageInfo>,
    I: Input + HasInfo,
    I::Output: DeserializeOwned + ReadLimit + DeserializeLimit,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> Unit: TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<DeallocateInput<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmCallInput<'x, V::Pointer, I>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmCallWithoutInfoInput<'x, V::Pointer, I>, Error = VmErrorOf<V>>,
    VmErrorOf<V>:
        From<ReadableMemoryErrorOf<V>> + From<WritableMemoryErrorOf<V>> + From<ExecutorError>,
{
    log::trace!("Call");
    let env = vm.get();
    let pointer = if I::HAS_INFO {
        let info = vm.get();
        let input = CosmwasmCallInput(
            marshall_in(vm, &env)?,
            marshall_in(vm, &info)?,
            passthrough_in(vm, message)?,
            PhantomData,
        );
        vm.call(input)
    } else {
        let input = CosmwasmCallWithoutInfoInput(
            marshall_in(vm, &env)?,
            passthrough_in(vm, message)?,
            PhantomData,
        );
        vm.call(input)
    }?;
    let result = marshall_out(vm, pointer)?;
    deallocate(vm, pointer)?;
    Ok(result)
}
