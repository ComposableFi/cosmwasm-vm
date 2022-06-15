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

use core::fmt::Debug;

use crate::{
    executor::{
        AllocateInput, CosmwasmCallInput, CosmwasmQueryInput, ExecuteInput, Executor,
        ExecutorError, ExecutorMemoryOf, InstantiateInput, ReplyInput,
    },
    has::Has,
    input::Input,
    loader::{Loader, LoaderErrorOf},
    memory::{ReadableMemoryErrorOf, WritableMemoryErrorOf},
    transaction::{Transactional, TransactionalErrorOf},
    vm::{VmErrorOf, VmInputOf},
};
use alloc::{format, string::String, vec::Vec};
use cosmwasm_minimal_std::{
    Addr, Binary, Coin, ContractResult, CosmosMsg, DeserializeLimit, Env, Event, MessageInfo,
    ReadLimit, Reply, ReplyOn, Response, SubMsg, SubMsgResponse, SubMsgResult, WasmMsg,
};
use serde::de::DeserializeOwned;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SystemError {
    UnsupportedMessage,
    FailedToSerialize,
    ContractExecutionFailure(String),
    AddressConversionFailed,
}

pub trait SystemEnv: Has<Env> + Has<MessageInfo> {}

#[derive(Debug)]
enum SubCallContinuation<E> {
    Continue(Option<Binary>),
    Reply(SubMsgResult),
    Abort(E),
}

pub type BankErrorOf<T> = <T as Bank>::Error;
pub type BankAccountIdOf<T> = <T as Bank>::AccountId;
pub trait Bank {
    type AccountId;
    type Error;
    fn transfer(
        &mut self,
        from: &Self::AccountId,
        to: &Self::AccountId,
        funds: Vec<Coin>,
    ) -> Result<(), Self::Error>;
}

pub type PeripheralsErrorOf<T> = <T as Peripherals>::Error;
pub type PeripheralsCodeOf<T> = <T as Peripherals>::CodeId;

pub trait Peripherals {
    type AccountId;
    type CodeId;
    type Error;
    fn contract_code(&mut self, contract: &Self::AccountId) -> Result<Self::CodeId, Self::Error>;
}

pub type SystemAccountIdOf<T> = <T as System>::AccountId;

pub type CosmwasmCodeId = u64;

pub trait System:
    Executor
    + Transactional
    + Loader<CodeId = CosmwasmCodeId, Output = Self>
    + SystemEnv
    + Bank<AccountId = SystemAccountIdOf<Self>>
    + Peripherals<AccountId = SystemAccountIdOf<Self>, CodeId = CosmwasmCodeId>
    + Sized
where
    for<'x> VmErrorOf<Self>: From<ReadableMemoryErrorOf<ExecutorMemoryOf<'x, Self>>>
        + From<WritableMemoryErrorOf<ExecutorMemoryOf<'x, Self>>>
        + From<ExecutorError>
        + From<SystemError>
        + From<TransactionalErrorOf<Self>>
        + From<LoaderErrorOf<Self>>
        + From<BankErrorOf<Self>>
        + From<PeripheralsErrorOf<Self>>
        + Debug,

    for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>
        + TryFrom<CosmwasmCallInput<'x, Self::Pointer, InstantiateInput>, Error = VmErrorOf<Self>>
        + TryFrom<CosmwasmCallInput<'x, Self::Pointer, ExecuteInput>, Error = VmErrorOf<Self>>
        + TryFrom<CosmwasmCallInput<'x, Self::Pointer, ReplyInput>, Error = VmErrorOf<Self>>
        + TryFrom<CosmwasmQueryInput<'x, Self::Pointer>, Error = VmErrorOf<Self>>,
{
    type AccountId: TryFrom<Addr>;

    fn cosmwasm_orchestrate_entrypoint<I>(
        &mut self,
        message: &[u8],
    ) -> Result<(Option<Binary>, Vec<Event>), VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>
            + TryFrom<CosmwasmCallInput<'x, Self::Pointer, I>, Error = VmErrorOf<Self>>,
        I: Input,
        I::Output: DeserializeOwned + ReadLimit + DeserializeLimit + Into<ContractResult<Response>>,
    {
        let mut events = Vec::<Event>::new();
        let mut event_handler = |event: Event| {
            events.push(event);
        };
        self.transaction_begin()?;
        match self.cosmwasm_orchestrate_call::<I>(message, &mut event_handler) {
            Ok(data) => {
                self.transaction_commit()?;
                Ok((data, events))
            }
            Err(e) => {
                self.transaction_rollback()?;
                Err(e)
            }
        }
    }

    fn cosmwasm_orchestrate_call<I>(
        &mut self,
        message: &[u8],
        mut event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, VmErrorOf<Self>>
    where
        for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<Self::Pointer>, Error = VmErrorOf<Self>>
            + TryFrom<CosmwasmCallInput<'x, Self::Pointer, I>, Error = VmErrorOf<Self>>,
        I: Input,
        I::Output: DeserializeOwned + ReadLimit + DeserializeLimit + Into<ContractResult<Response>>,
    {
        log::debug!("OrchestrateCall");
        let env: Env = self.get();
        let info = self.get();
        let output = self
            .cosmwasm_call::<I>(env.clone(), info, message)
            .map(Into::into);
        log::debug!("Output: {:?}", output);
        match output {
            Ok(ContractResult::Ok(Response {
                messages,
                attributes,
                events,
                data,
                ..
            })) => {
                // https://github.com/CosmWasm/wasmd/blob/ac92fdcf37388cc8dc24535f301f64395f8fb3da/x/wasm/keeper/events.go#L16
                if attributes.len() > 0 {
                    event_handler(Event::new("wasm".into(), attributes));
                }
                // https://github.com/CosmWasm/wasmd/blob/ac92fdcf37388cc8dc24535f301f64395f8fb3da/x/wasm/keeper/events.go#L29
                events.into_iter().for_each(|Event { ty, attributes, .. }| {
                    event_handler(Event::new(format!("wasm-{}", ty), attributes))
                });

                messages.into_iter().try_fold(
                    data,
                    |current,
                     SubMsg {
                         id,
                         msg,
                         gas_limit,
                         reply_on,
                     }|
                     -> Result<Option<Binary>, VmErrorOf<Self>> {
                        log::debug!("Executing submessages");
                        let mut sub_events = Vec::<Event>::new();
                        let mut sub_event_handler = |event: Event| {
                            event_handler(event.clone());
                            sub_events.push(event);
                        };
                        self.transaction_begin()?;
                        let sub_res = match msg {
                            CosmosMsg::Wasm(WasmMsg::Execute {
                                contract_addr,
                                msg: Binary(msg),
                                funds,
                            }) => {
                                let contract_addr = Addr::unchecked(contract_addr)
                                    .try_into()
                                    .map_err(|_| SystemError::AddressConversionFailed)?;
                                self.transfer(
                                    &env.contract
                                        .address
                                        .clone()
                                        .try_into()
                                        .map_err(|_| SystemError::AddressConversionFailed)?,
                                    &contract_addr,
                                    funds,
                                )?;
                                let code_id = self.contract_code(&contract_addr)?;
                                self.load(code_id)?
                                    .cosmwasm_orchestrate_call::<ExecuteInput>(
                                        &msg,
                                        &mut sub_event_handler,
                                    )
                            }
                            _ => Err(SystemError::UnsupportedMessage.into()),
                        };

                        log::debug!("Submessage result: {:?}", sub_res);

                        let sub_cont = match (sub_res, reply_on.clone()) {
                            (Ok(v), ReplyOn::Never | ReplyOn::Error) => {
                                log::debug!("Commit & Continue");
                                self.transaction_commit()?;
                                SubCallContinuation::Continue(v)
                            }
                            (Ok(v), ReplyOn::Always | ReplyOn::Success) => {
                                log::debug!("Commit & Reply");
                                self.transaction_commit()?;
                                let events = sub_events.clone();
                                SubCallContinuation::Reply(SubMsgResult::Ok(SubMsgResponse {
                                    events,
                                    data: v,
                                }))
                            }
                            (Err(e), ReplyOn::Always | ReplyOn::Error) => {
                                log::debug!("Rollback & Reply");
                                self.transaction_rollback()?;
                                SubCallContinuation::Reply(SubMsgResult::Err(format!("{:?}", e)))
                            }
                            (Err(e), ReplyOn::Never | ReplyOn::Success) => {
                                log::debug!("Rollback & Abort");
                                self.transaction_rollback()?;
                                SubCallContinuation::Abort(e)
                            }
                        };

                        log::debug!("Submessage cont: {:?}", sub_cont);

                        match sub_cont {
                            // Current value might be overwritten.
                            SubCallContinuation::Continue(v) => Ok(v.or_else(|| current)),
                            // Abort result in no value indeed.
                            SubCallContinuation::Abort(e) => Err(e),
                            // Might be overwritten again.
                            SubCallContinuation::Reply(response) => {
                                let raw_response = serde_json::to_vec(&Reply {
                                    id,
                                    result: response,
                                })
                                .map_err(|_| SystemError::FailedToSerialize)?;
                                self.cosmwasm_orchestrate_call::<ReplyInput>(
                                    &raw_response,
                                    &mut event_handler,
                                )
                                .map(|v| v.or_else(|| current))
                            }
                        }
                    },
                )
            }
            Ok(ContractResult::Err(e)) => Err(SystemError::ContractExecutionFailure(e).into()),
            Err(e) => Err(e),
        }
    }
}
