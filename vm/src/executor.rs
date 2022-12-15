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
use cosmwasm_std::{Binary, ContractResult, Empty, Env, MessageInfo, QueryRequest, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod read_limits {
    /// A mibi (mega binary)
    const MI: usize = 1024 * 1024;
    /// Max length (in bytes) of the result data from an instantiate call.
    pub const RESULT_INSTANTIATE: usize = 64 * MI;
    /// Max length (in bytes) of the result data from an execute call.
    pub const RESULT_EXECUTE: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a migrate call.
    pub const RESULT_MIGRATE: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a sudo call.
    pub const RESULT_SUDO: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a reply call.
    pub const RESULT_REPLY: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a query call.
    pub const RESULT_QUERY: usize = 64 * MI;
    /// Max length (in bytes) of the query data from a `query_chain` call.
    pub const REQUEST_QUERY: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a `ibc_channel_open` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_CHANNEL_OPEN: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a `ibc_channel_connect` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_CHANNEL_CONNECT: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a `ibc_channel_close` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_CHANNEL_CLOSE: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a `ibc_packet_receive` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_PACKET_RECEIVE: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a `ibc_packet_ack` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_PACKET_ACK: usize = 64 * MI;
    /// Max length (in bytes) of the result data from a `ibc_packet_timeout` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_PACKET_TIMEOUT: usize = 64 * MI;
}

/// The limits for the JSON deserialization.
///
/// Those limits are not used when the Rust JSON deserializer is bypassed by using the
/// public `call_*_raw` functions directly.
pub mod deserialization_limits {
    /// A kibi (kilo binary)
    const KI: usize = 1024;
    /// Max length (in bytes) of the result data from an instantiate call.
    pub const RESULT_INSTANTIATE: usize = 256 * KI;
    /// Max length (in bytes) of the result data from an execute call.
    pub const RESULT_EXECUTE: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a migrate call.
    pub const RESULT_MIGRATE: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a sudo call.
    pub const RESULT_SUDO: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a reply call.
    pub const RESULT_REPLY: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a query call.
    pub const RESULT_QUERY: usize = 256 * KI;
    /// Max length (in bytes) of the query data from a `query_chain` call.
    pub const REQUEST_QUERY: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a `ibc_channel_open` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_CHANNEL_OPEN: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a `ibc_channel_connect` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_CHANNEL_CONNECT: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a `ibc_channel_close` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_CHANNEL_CLOSE: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a `ibc_packet_receive` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_PACKET_RECEIVE: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a `ibc_packet_ack` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_PACKET_ACK: usize = 256 * KI;
    /// Max length (in bytes) of the result data from a `ibc_packet_timeout` call.
    #[cfg(feature = "stargate")]
    pub const RESULT_IBC_PACKET_TIMEOUT: usize = 256 * KI;
}

pub type CosmwasmExecutionResult<T = Empty> = ContractResult<Response<T>>;
pub type CosmwasmQueryResult = ContractResult<QueryResponse>;
pub type CosmwasmReplyResult<T = Empty> = ContractResult<Response<T>>;
pub type CosmwasmMigrateResult<T = Empty> = ContractResult<Response<T>>;

pub type QueryResponse = Binary;

pub trait DeserializeLimit {
    fn deserialize_limit() -> usize;
}

pub trait ReadLimit {
    fn read_limit() -> usize;
}

impl<C> DeserializeLimit for QueryRequest<C> {
    fn deserialize_limit() -> usize {
        deserialization_limits::REQUEST_QUERY
    }
}

impl<C> ReadLimit for QueryRequest<C> {
    fn read_limit() -> usize {
        read_limits::REQUEST_QUERY
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReplyResult<T = Empty>(pub CosmwasmExecutionResult<T>);
impl<T> DeserializeLimit for ReplyResult<T> {
    fn deserialize_limit() -> usize {
        deserialization_limits::RESULT_REPLY
    }
}
impl<T> ReadLimit for ReplyResult<T> {
    fn read_limit() -> usize {
        read_limits::RESULT_REPLY
    }
}
impl<T> From<ReplyResult<T>> for ContractResult<Response<T>> {
    fn from(ReplyResult(result): ReplyResult<T>) -> Self {
        result
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct QueryResult(pub CosmwasmQueryResult);
impl DeserializeLimit for QueryResult {
    fn deserialize_limit() -> usize {
        deserialization_limits::RESULT_QUERY
    }
}
impl ReadLimit for QueryResult {
    fn read_limit() -> usize {
        read_limits::RESULT_QUERY
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExecuteResult<T = Empty>(pub CosmwasmExecutionResult<T>);
impl<T> DeserializeLimit for ExecuteResult<T> {
    fn deserialize_limit() -> usize {
        deserialization_limits::RESULT_EXECUTE
    }
}
impl<T> ReadLimit for ExecuteResult<T> {
    fn read_limit() -> usize {
        read_limits::RESULT_EXECUTE
    }
}
impl<T> From<ExecuteResult<T>> for ContractResult<Response<T>> {
    fn from(ExecuteResult(result): ExecuteResult<T>) -> Self {
        result
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InstantiateResult<T = Empty>(pub CosmwasmExecutionResult<T>);
impl<T> DeserializeLimit for InstantiateResult<T> {
    fn deserialize_limit() -> usize {
        deserialization_limits::RESULT_INSTANTIATE
    }
}
impl<T> ReadLimit for InstantiateResult<T> {
    fn read_limit() -> usize {
        read_limits::RESULT_INSTANTIATE
    }
}
impl<T> From<InstantiateResult<T>> for ContractResult<Response<T>> {
    fn from(InstantiateResult(result): InstantiateResult<T>) -> Self {
        result
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MigrateResult<T = Empty>(pub CosmwasmExecutionResult<T>);
impl<T> DeserializeLimit for MigrateResult<T> {
    fn deserialize_limit() -> usize {
        deserialization_limits::RESULT_MIGRATE
    }
}
impl<T> ReadLimit for MigrateResult<T> {
    fn read_limit() -> usize {
        read_limits::RESULT_MIGRATE
    }
}
impl<T> From<MigrateResult<T>> for ContractResult<Response<T>> {
    fn from(MigrateResult(result): MigrateResult<T>) -> Self {
        result
    }
}

pub mod ibc {
    #![cfg(feature = "stargate")]

    use super::{
        deserialization_limits, read_limits, AsFunctionName, ContractResult, Debug, Deserialize,
        DeserializeLimit, Empty, HasInfo, Input, PhantomData, ReadLimit, Response, Serialize,
    };
    use cosmwasm_std::{Ibc3ChannelOpenResponse, IbcBasicResponse, IbcReceiveResponse};

    /// Response to the low level `ibc_channel_open` call.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcChannelOpenResult(pub ContractResult<Option<Ibc3ChannelOpenResponse>>);
    impl DeserializeLimit for IbcChannelOpenResult {
        fn deserialize_limit() -> usize {
            deserialization_limits::RESULT_IBC_CHANNEL_OPEN
        }
    }
    impl ReadLimit for IbcChannelOpenResult {
        fn read_limit() -> usize {
            read_limits::RESULT_IBC_CHANNEL_OPEN
        }
    }

    /// Response to the low level `ibc_channel_connect` call.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcChannelConnectResult<T = Empty>(pub ContractResult<IbcBasicResponse<T>>);
    impl<T> DeserializeLimit for IbcChannelConnectResult<T> {
        fn deserialize_limit() -> usize {
            deserialization_limits::RESULT_IBC_CHANNEL_CONNECT
        }
    }
    impl<T> ReadLimit for IbcChannelConnectResult<T> {
        fn read_limit() -> usize {
            read_limits::RESULT_IBC_CHANNEL_CONNECT
        }
    }
    impl<T> From<IbcChannelConnectResult<T>> for ContractResult<Response<T>> {
        fn from(IbcChannelConnectResult(result): IbcChannelConnectResult<T>) -> Self {
            match result {
                ContractResult::Ok(IbcBasicResponse {
                    messages,
                    attributes,
                    events,
                    ..
                }) => ContractResult::Ok(
                    Response::new()
                        .add_submessages(messages)
                        .add_attributes(attributes)
                        .add_events(events),
                ),
                ContractResult::Err(x) => ContractResult::Err(x),
            }
        }
    }

    /// Response to the low level `ibc_channel_close` call.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcChannelCloseResult<T = Empty>(pub ContractResult<IbcBasicResponse<T>>);
    impl<T> DeserializeLimit for IbcChannelCloseResult<T> {
        fn deserialize_limit() -> usize {
            deserialization_limits::RESULT_IBC_CHANNEL_CLOSE
        }
    }
    impl<T> ReadLimit for IbcChannelCloseResult<T> {
        fn read_limit() -> usize {
            read_limits::RESULT_IBC_CHANNEL_CLOSE
        }
    }
    impl<T> From<IbcChannelCloseResult<T>> for ContractResult<Response<T>> {
        fn from(IbcChannelCloseResult(result): IbcChannelCloseResult<T>) -> Self {
            match result {
                ContractResult::Ok(IbcBasicResponse {
                    messages,
                    attributes,
                    events,
                    ..
                }) => ContractResult::Ok(
                    Response::new()
                        .add_submessages(messages)
                        .add_attributes(attributes)
                        .add_events(events),
                ),
                ContractResult::Err(x) => ContractResult::Err(x),
            }
        }
    }

    /// Response to the low level `ibc_packet_receive` call.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcPacketReceiveResult<T = Empty>(pub ContractResult<IbcReceiveResponse<T>>);
    impl<T> DeserializeLimit for IbcPacketReceiveResult<T> {
        fn deserialize_limit() -> usize {
            deserialization_limits::RESULT_IBC_PACKET_RECEIVE
        }
    }
    impl<T> ReadLimit for IbcPacketReceiveResult<T> {
        fn read_limit() -> usize {
            read_limits::RESULT_IBC_PACKET_RECEIVE
        }
    }
    impl<T> From<IbcPacketReceiveResult<T>> for ContractResult<Response<T>> {
        fn from(IbcPacketReceiveResult(result): IbcPacketReceiveResult<T>) -> Self {
            match result {
                ContractResult::Ok(IbcReceiveResponse {
                    messages,
                    attributes,
                    events,
                    acknowledgement,
                    ..
                }) => ContractResult::Ok(
                    Response::new()
                        .add_submessages(messages)
                        .add_attributes(attributes)
                        .add_events(events)
                        .set_data(acknowledgement),
                ),
                ContractResult::Err(x) => ContractResult::Err(x),
            }
        }
    }

    /// Response to the low level `ibc_packet_ack` call.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcPacketAckResult<T = Empty>(pub ContractResult<IbcBasicResponse<T>>);
    impl<T> DeserializeLimit for IbcPacketAckResult<T> {
        fn deserialize_limit() -> usize {
            deserialization_limits::RESULT_IBC_PACKET_ACK
        }
    }
    impl<T> ReadLimit for IbcPacketAckResult<T> {
        fn read_limit() -> usize {
            read_limits::RESULT_IBC_PACKET_ACK
        }
    }
    impl<T> From<IbcPacketAckResult<T>> for ContractResult<Response<T>> {
        fn from(IbcPacketAckResult(result): IbcPacketAckResult<T>) -> Self {
            match result {
                ContractResult::Ok(IbcBasicResponse {
                    messages,
                    attributes,
                    events,
                    ..
                }) => ContractResult::Ok(
                    Response::new()
                        .add_submessages(messages)
                        .add_attributes(attributes)
                        .add_events(events),
                ),
                ContractResult::Err(x) => ContractResult::Err(x),
            }
        }
    }

    /// Response to the low level `ibc_packet_timeout` call.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcPacketTimeoutResult<T = Empty>(pub ContractResult<IbcBasicResponse<T>>);
    impl<T> DeserializeLimit for IbcPacketTimeoutResult<T> {
        fn deserialize_limit() -> usize {
            deserialization_limits::RESULT_IBC_PACKET_TIMEOUT
        }
    }
    impl<T> ReadLimit for IbcPacketTimeoutResult<T> {
        fn read_limit() -> usize {
            read_limits::RESULT_IBC_PACKET_TIMEOUT
        }
    }
    impl<T> From<IbcPacketTimeoutResult<T>> for ContractResult<Response<T>> {
        fn from(IbcPacketTimeoutResult(result): IbcPacketTimeoutResult<T>) -> Self {
            match result {
                ContractResult::Ok(IbcBasicResponse {
                    messages,
                    attributes,
                    events,
                    ..
                }) => ContractResult::Ok(
                    Response::new()
                        .add_submessages(messages)
                        .add_attributes(attributes)
                        .add_events(events),
                ),
                ContractResult::Err(x) => ContractResult::Err(x),
            }
        }
    }

    /// Strong type representing a call to `ibc_channel_open` export.
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcChannelOpenCall;
    impl Input for IbcChannelOpenCall {
        type Output = IbcChannelOpenResult;
    }
    impl AsFunctionName for IbcChannelOpenCall {
        const NAME: &'static str = "ibc_channel_open";
    }
    impl HasInfo for IbcChannelOpenCall {
        const HAS_INFO: bool = false;
    }

    /// Strong type representing a call to `ibc_channel_connect` export.
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcChannelConnectCall<T = Empty>(PhantomData<T>);
    impl<T> Input for IbcChannelConnectCall<T> {
        type Output = IbcChannelConnectResult<T>;
    }
    impl<T> AsFunctionName for IbcChannelConnectCall<T> {
        const NAME: &'static str = "ibc_channel_connect";
    }
    impl<T> HasInfo for IbcChannelConnectCall<T> {
        const HAS_INFO: bool = false;
    }

    /// Strong type representing a call to `ibc_channel_close` export.
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcChannelCloseCall<T = Empty>(PhantomData<T>);
    impl<T> Input for IbcChannelCloseCall<T> {
        type Output = IbcChannelCloseResult<T>;
    }
    impl<T> AsFunctionName for IbcChannelCloseCall<T> {
        const NAME: &'static str = "ibc_channel_close";
    }
    impl<T> HasInfo for IbcChannelCloseCall<T> {
        const HAS_INFO: bool = false;
    }

    /// Strong type representing a call to `ibc_packet_receive` export.
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcPacketReceiveCall<T = Empty>(PhantomData<T>);
    impl<T> Input for IbcPacketReceiveCall<T> {
        type Output = IbcPacketReceiveResult<T>;
    }
    impl<T> AsFunctionName for IbcPacketReceiveCall<T> {
        const NAME: &'static str = "ibc_packet_receive";
    }
    impl<T> HasInfo for IbcPacketReceiveCall<T> {
        const HAS_INFO: bool = false;
    }

    /// Strong type representing a call to `ibc_packet_ack` export.
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcPacketAckCall<T = Empty>(PhantomData<T>);
    impl<T> Input for IbcPacketAckCall<T> {
        type Output = IbcPacketAckResult<T>;
    }
    impl<T> AsFunctionName for IbcPacketAckCall<T> {
        const NAME: &'static str = "ibc_packet_ack";
    }
    impl<T> HasInfo for IbcPacketAckCall<T> {
        const HAS_INFO: bool = false;
    }

    /// Strong type representing a call to `ibc_packet_timeout` export.
    #[allow(clippy::module_name_repetitions)]
    pub struct IbcPacketTimeoutCall<T = Empty>(PhantomData<T>);
    impl<T> Input for IbcPacketTimeoutCall<T> {
        type Output = IbcPacketTimeoutResult<T>;
    }
    impl<T> AsFunctionName for IbcPacketTimeoutCall<T> {
        const NAME: &'static str = "ibc_packet_timeout";
    }
    impl<T> HasInfo for IbcPacketTimeoutCall<T> {
        const HAS_INFO: bool = false;
    }
}

/// The type representing a call to a contract `allocate` export.
pub struct AllocateCall<Pointer>(pub Pointer);
impl<Pointer> Input for AllocateCall<Pointer> {
    type Output = Pointer;
}
impl<Pointer> AsFunctionName for AllocateCall<Pointer> {
    const NAME: &'static str = "allocate";
}

pub struct Unit;

/// The type representing a call to a contract `deallocate` export.
pub struct DeallocateCall<Pointer>(pub Pointer);
impl<Pointer> Input for DeallocateCall<Pointer> {
    type Output = Unit;
}
impl<Pointer> AsFunctionName for DeallocateCall<Pointer> {
    const NAME: &'static str = "deallocate";
}

/// The type representing a call to a contract `query` export.
pub struct QueryCall;
impl Input for QueryCall {
    type Output = QueryResult;
}
impl AsFunctionName for QueryCall {
    const NAME: &'static str = "query";
}
impl HasInfo for QueryCall {
    const HAS_INFO: bool = false;
}

/// The type representing a call to a contract `instantiate` export.
pub struct InstantiateCall<T = Empty>(PhantomData<T>);
impl<T> Input for InstantiateCall<T> {
    type Output = InstantiateResult<T>;
}
impl<T> AsFunctionName for InstantiateCall<T> {
    const NAME: &'static str = "instantiate";
}
impl<T> HasInfo for InstantiateCall<T> {
    const HAS_INFO: bool = true;
}

/// The type representing a call to a contract `execute` export.
pub struct ExecuteCall<T = Empty>(PhantomData<T>);
impl<T> Input for ExecuteCall<T> {
    type Output = ExecuteResult<T>;
}
impl<T> AsFunctionName for ExecuteCall<T> {
    const NAME: &'static str = "execute";
}
impl<T> HasInfo for ExecuteCall<T> {
    const HAS_INFO: bool = true;
}

/// The type representing a call to a contract `reply` export.
pub struct ReplyCall<T = Empty>(PhantomData<T>);
impl<T> Input for ReplyCall<T> {
    type Output = ReplyResult<T>;
}
impl<T> AsFunctionName for ReplyCall<T> {
    const NAME: &'static str = "reply";
}
impl<T> HasInfo for ReplyCall<T> {
    const HAS_INFO: bool = false;
}

/// The type representing a call to a contract `migrate` export.
pub struct MigrateCall<T = Empty>(PhantomData<T>);
impl<T> Input for MigrateCall<T> {
    type Output = MigrateResult<T>;
}
impl<T> AsFunctionName for MigrateCall<T> {
    const NAME: &'static str = "migrate";
}
impl<T> HasInfo for MigrateCall<T> {
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
#[allow(clippy::module_name_repetitions)]
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
    /// Max key length for `db_write/db_read/db_remove/db_scan` (when VM reads the key argument from Wasm
    /// memory)
    pub const MAX_LENGTH_DB_KEY: usize = 64 * KI;
    /// Max value length for `db_write` (when VM reads the value argument from Wasm memory)
    pub const MAX_LENGTH_DB_VALUE: usize = 128 * KI;
    /// Typically 20 (Cosmos SDK, Ethereum), 32 (Nano, Substrate) or 54 (`MockApi`)
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
    /// Max number of batch Ed25519 messages / signatures / `public_keys`.
    /// This is an arbitrary value, for performance / memory contraints. If you need to batch-verify a
    /// larger number of signatures, let us know.
    pub const MAX_COUNT_ED25519_BATCH: usize = 256;
    /// Max length for a debug message
    pub const MAX_LENGTH_DEBUG: usize = 2 * MI;
    /// Max length for an abort message
    pub const MAX_LENGTH_ABORT: usize = 2 * MI;
    /// Max length of a message hash
    pub const MAX_LENGTH_MESSAGE_HASH: usize = 32;
    /// Length of an edcsa signature
    pub const EDCSA_SIGNATURE_LENGTH: usize = 64;
    /// Max length for edcsa public key
    pub const MAX_LENGTH_EDCSA_PUBKEY_LENGTH: usize = 65;
    /// Length of an eddsa public key
    pub const EDDSA_PUBKEY_LENGTH: usize = 32;
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
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateCall<P>, Error = VmErrorOf<V>>,
    P: Copy + TryFrom<L> + Debug + for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>: From<ExecutorError>,
{
    let len_value = P::try_from(len).map_err(|_| ExecutorError::AllocationWouldOverflow)?;
    let result = vm.call(AllocateCall(len_value))?;
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
    for<'x> VmInputOf<'x, V>: TryFrom<DeallocateCall<V::Pointer>, Error = VmErrorOf<V>>,
    VmErrorOf<V>: From<ExecutorError>,
{
    log::trace!("Deallocate");
    vm.call(DeallocateCall(pointer))?;
    Ok(())
}

pub fn passthrough_in_to<V>(
    vm: &mut V,
    destination: V::Pointer,
    data: &[u8],
) -> Result<(), VmErrorOf<V>>
where
    V: VM + ReadWriteMemory,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateCall<V::Pointer>, Error = VmErrorOf<V>>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>:
        From<ReadableMemoryErrorOf<V>> + From<WritableMemoryErrorOf<V>> + From<ExecutorError>,
{
    RawIntoRegion::try_from(Write(vm, destination, data))?;
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
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateCall<V::Pointer>, Error = VmErrorOf<V>>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>:
        From<ReadableMemoryErrorOf<V>> + From<WritableMemoryErrorOf<V>> + From<ExecutorError>,
{
    log::trace!("PassthroughIn");
    let pointer = allocate::<_, _, usize>(vm, data.len())?;
    passthrough_in_to(vm, pointer, data)?;
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
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateCall<V::Pointer>, Error = VmErrorOf<V>>,
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
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateCall<V::Pointer>, Error = VmErrorOf<V>>,
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
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateCall<V::Pointer>, Error = VmErrorOf<V>>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    VmErrorOf<V>: From<ReadableMemoryErrorOf<V>> + From<ExecutorError>,
    T: serde::de::DeserializeOwned + ReadLimit + DeserializeLimit,
{
    log::trace!("MarshallOut");
    let output = passthrough_out::<V, T>(vm, pointer)?;
    Ok(serde_json::from_slice(&output).map_err(|_| ExecutorError::FailedToDeserialize)?)
}

/// Execute a generic contract export (`instantiate`, `execute`, `migrate` etc...), providing the custom raw `message` input.
///
/// # Arguments
///
/// * `vm` - the virtual machine.
/// * `message` - the contract message passed to the export, usually specific to the contract (`InstantiateMsg`, `ExecuteMsg` etc...).
///
/// Returns either the associated `I::Output` or a `VmErrorOf<V>`.
pub fn cosmwasm_call<I, V>(vm: &mut V, message: &[u8]) -> Result<I::Output, VmErrorOf<V>>
where
    V: VM + ReadWriteMemory + Has<Env> + Has<MessageInfo>,
    I: Input + HasInfo,
    I::Output: DeserializeOwned + ReadLimit + DeserializeLimit,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> Unit: TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateCall<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<DeallocateCall<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmCallInput<'x, V::Pointer, I>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmCallWithoutInfoInput<'x, V::Pointer, I>, Error = VmErrorOf<V>>,
    VmErrorOf<V>:
        From<ReadableMemoryErrorOf<V>> + From<WritableMemoryErrorOf<V>> + From<ExecutorError>,
{
    log::trace!("Call {}", alloc::string::String::from_utf8_lossy(message));
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

/// Execute a generic contract export (`instantiate`, `execute`, `migrate` etc...), providing the high level message.
///
/// # Arguments
///
/// * `vm` - the virtual machine.
/// * `message` - the contract message passed to the export, usually specific to the contract (`InstantiateMsg`, `ExecuteMsg` etc...).
///
/// Returns either the associated `I::Output` or a `VmErrorOf<V>`.
pub fn cosmwasm_call_serialize<I, V, M>(vm: &mut V, message: &M) -> Result<I::Output, VmErrorOf<V>>
where
    M: Serialize,
    V: VM + ReadWriteMemory + Has<Env> + Has<MessageInfo>,
    I: Input + HasInfo,
    I::Output: DeserializeOwned + ReadLimit + DeserializeLimit,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> Unit: TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateCall<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<DeallocateCall<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmCallInput<'x, V::Pointer, I>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmCallWithoutInfoInput<'x, V::Pointer, I>, Error = VmErrorOf<V>>,
    VmErrorOf<V>:
        From<ReadableMemoryErrorOf<V>> + From<WritableMemoryErrorOf<V>> + From<ExecutorError>,
{
    cosmwasm_call(
        vm,
        &serde_json::to_vec(message).map_err(|_| ExecutorError::FailedToSerialize)?,
    )
}
