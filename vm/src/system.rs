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
    executor::{cosmwasm_call, AllocateInput, CosmwasmCallInput, ExecutorError},
    has::Has,
    input::Input,
    loader::{Loader, LoaderErrorOf},
    memory::{ReadWriteMemory, ReadableMemoryErrorOf, WritableMemoryErrorOf},
    transaction::{Transactional, TransactionalErrorOf},
    vm::{VmErrorOf, VmInputOf, VmOutputOf, VM},
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
}

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
        funds: &[Coin],
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

pub type CosmwasmCodeId = u64;

pub struct LoadContract {
    pub env: Env,
    pub info: MessageInfo,
    pub code_id: CosmwasmCodeId,
}

pub fn cosmwasm_system_entrypoint<I, V>(
    vm: &mut V,
    message: &[u8],
) -> Result<(Option<Binary>, Vec<Event>), VmErrorOf<V>>
where
    V: VM
        + ReadWriteMemory
        + Transactional
        + Loader<CodeId = LoadContract, Output = V>
        + Bank
        + Peripherals<AccountId = BankAccountIdOf<V>, CodeId = CosmwasmCodeId>
        + ReadWriteMemory
        + Has<Env>
        + Has<MessageInfo>,
    I: Input,
    I::Output: DeserializeOwned + ReadLimit + DeserializeLimit + Into<ContractResult<Response>>,
    VmErrorOf<V>: From<ReadableMemoryErrorOf<V>>
        + From<WritableMemoryErrorOf<V>>
        + From<ExecutorError>
        + From<SystemError>
        + From<TransactionalErrorOf<V>>
        + From<LoaderErrorOf<V>>
        + From<BankErrorOf<V>>
        + From<PeripheralsErrorOf<V>>
        + Debug,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmCallInput<'x, V::Pointer, I>, Error = VmErrorOf<V>>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    BankAccountIdOf<V>: TryFrom<Addr, Error = VmErrorOf<V>>,
{
    log::debug!("OrchestrateEntrypoint");
    let mut events = Vec::<Event>::new();
    let mut event_handler = |event: Event| {
        events.push(event);
    };
    vm.transaction_begin()?;
    match cosmwasm_system_call(vm, message, &mut event_handler) {
        Ok(data) => {
            vm.transaction_commit()?;
            Ok((data, events))
        }
        Err(e) => {
            vm.transaction_rollback()?;
            Err(e)
        }
    }
}

fn cosmwasm_system_call<I, V>(
    vm: &mut V,
    message: &[u8],
    mut event_handler: &mut dyn FnMut(Event),
) -> Result<Option<Binary>, VmErrorOf<V>>
where
    V: VM
        + ReadWriteMemory
        + Transactional
        + Loader<CodeId = LoadContract, Output = V>
        + Bank
        + Peripherals<AccountId = BankAccountIdOf<V>, CodeId = CosmwasmCodeId>
        + ReadWriteMemory
        + Has<Env>
        + Has<MessageInfo>,
    I: Input,
    I::Output: DeserializeOwned + ReadLimit + DeserializeLimit + Into<ContractResult<Response>>,
    VmErrorOf<V>: From<ReadableMemoryErrorOf<V>>
        + From<WritableMemoryErrorOf<V>>
        + From<ExecutorError>
        + From<SystemError>
        + From<TransactionalErrorOf<V>>
        + From<LoaderErrorOf<V>>
        + From<BankErrorOf<V>>
        + From<PeripheralsErrorOf<V>>
        + Debug,
    for<'x> VmInputOf<'x, V>: TryFrom<AllocateInput<V::Pointer>, Error = VmErrorOf<V>>
        + TryFrom<CosmwasmCallInput<'x, V::Pointer, I>, Error = VmErrorOf<V>>,
    V::Pointer: for<'x> TryFrom<VmOutputOf<'x, V>, Error = VmErrorOf<V>>,
    BankAccountIdOf<V>: TryFrom<Addr, Error = VmErrorOf<V>>,
{
    log::debug!("OrchestrateCall");
    let env: Env = vm.get();
    let info: MessageInfo = vm.get();
    let output = cosmwasm_call(vm, &env, &info, message).map(Into::into);
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
                move |current,
                      SubMsg {
                          id,
                          msg,
                          gas_limit,
                          reply_on,
                      }|
                      -> Result<Option<Binary>, VmErrorOf<V>> {
                    log::debug!("Executing submessages");
                    let mut sub_events = Vec::<Event>::new();
                    let mut sub_event_handler = |event: Event| {
                        event_handler(event.clone());
                        sub_events.push(event);
                    };
                    vm.transaction_begin()?;
                    let sub_res = match msg {
                        CosmosMsg::Wasm(WasmMsg::Execute {
                            contract_addr,
                            msg: Binary(msg),
                            funds,
                        }) => {
                            let contract_addr = Addr::unchecked(contract_addr).try_into()?;
                            vm.transfer(
                                &env.contract.address.clone().try_into()?,
                                &contract_addr,
                                &funds,
                            )?;
                            let code_id = vm.contract_code(&contract_addr)?;
                            let mut sub_vm = vm.load(LoadContract {
                                env: env.clone(),
                                info: MessageInfo {
                                    sender: env.contract.address.clone(),
                                    funds,
                                },
                                code_id,
                            })?;
                            cosmwasm_system_call(&mut sub_vm, &msg, &mut sub_event_handler)
                        }
                        _ => Err(SystemError::UnsupportedMessage.into()),
                    };

                    log::debug!("Submessage result: {:?}", sub_res);

                    let sub_cont = match (sub_res, reply_on.clone()) {
                        (Ok(v), ReplyOn::Never | ReplyOn::Error) => {
                            log::debug!("Commit & Continue");
                            vm.transaction_commit()?;
                            SubCallContinuation::Continue(v)
                        }
                        (Ok(v), ReplyOn::Always | ReplyOn::Success) => {
                            log::debug!("Commit & Reply");
                            vm.transaction_commit()?;
                            let events = sub_events.clone();
                            SubCallContinuation::Reply(SubMsgResult::Ok(SubMsgResponse {
                                events,
                                data: v,
                            }))
                        }
                        (Err(e), ReplyOn::Always | ReplyOn::Error) => {
                            log::debug!("Rollback & Reply");
                            vm.transaction_rollback()?;
                            SubCallContinuation::Reply(SubMsgResult::Err(format!("{:?}", e)))
                        }
                        (Err(e), ReplyOn::Never | ReplyOn::Success) => {
                            log::debug!("Rollback & Abort");
                            vm.transaction_rollback()?;
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
                            cosmwasm_system_call(vm, &raw_response, &mut event_handler)
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
