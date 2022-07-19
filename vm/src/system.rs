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
    executor::{
        cosmwasm_call, AllocateInput, CosmwasmCallInput, CosmwasmCallWithoutInfoInput,
        DeallocateInput, ExecuteInput, ExecutorError, HasInfo, InstantiateInput, MigrateInput,
        ReplyInput, Unit,
    },
    has::Has,
    input::{Input, OutputOf},
    memory::{PointerOf, ReadWriteMemory, ReadableMemoryErrorOf, WritableMemoryErrorOf},
    transaction::{Transactional, TransactionalErrorOf},
    vm::{
        VmAddressOf, VmErrorOf, VmGasCheckpoint, VmInputOf, VmMessageCustomOf, VmOutputOf,
        VmQueryCustomOf, VM,
    },
};
use alloc::{format, string::String, vec, vec::Vec};
use core::fmt::Debug;
use cosmwasm_minimal_std::{
    AllBalanceResponse, BalanceResponse, BankMsg, BankQuery, Binary, ContractResult, CosmosMsg,
    CosmwasmQueryResult, DeserializeLimit, Env, Event, MessageInfo, QueryRequest, QueryResult,
    ReadLimit, Reply, ReplyOn, Response, SubMsg, SubMsgResponse, SubMsgResult, SystemResult,
    WasmMsg, WasmQuery,
};
use serde::de::DeserializeOwned;

/// Errors likely to happen while a VM is executing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SystemError {
    UnsupportedMessage,
    FailedToSerialize,
    ContractExecutionFailure(String),
    ImmutableCantMigrate,
    MustBeAdmin,
}

#[derive(Debug)]
enum SubCallContinuation<E> {
    Continue(Option<Binary>),
    Reply(SubMsgResult),
    Abort(E),
}

pub type CosmwasmCodeId = u64;

/// Minimum metadata associated to contracts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CosmwasmContractMeta {
    pub code_id: CosmwasmCodeId,
    pub admin: Option<String>,
    pub label: String,
}

pub trait CosmwasmBaseVM = VM<CodeId = CosmwasmContractMeta, StorageKey = Vec<u8>, StorageValue = Vec<u8>>
    + ReadWriteMemory
    + Transactional
    + Has<Env>
    + Has<MessageInfo>
where
    VmMessageCustomOf<Self>: DeserializeOwned + Debug,
    VmQueryCustomOf<Self>: DeserializeOwned + Debug,
    VmAddressOf<Self>: Clone + TryFrom<String, Error = VmErrorOf<Self>>,
    VmErrorOf<Self>: From<ReadableMemoryErrorOf<Self>>
        + From<WritableMemoryErrorOf<Self>>
        + From<ExecutorError>
        + From<SystemError>
        + From<TransactionalErrorOf<Self>>
        + Debug,
    for<'x> VmInputOf<'x, Self>: TryFrom<AllocateInput<PointerOf<Self>>, Error = VmErrorOf<Self>>,
    PointerOf<Self>: for<'x> TryFrom<VmOutputOf<'x, Self>, Error = VmErrorOf<Self>>;

pub trait CosmwasmCallVM<I> = CosmwasmBaseVM
where
    for<'x> Unit: TryFrom<VmOutputOf<'x, Self>, Error = VmErrorOf<Self>>,
    for<'x> VmInputOf<'x, Self>: TryFrom<DeallocateInput<PointerOf<Self>>, Error = VmErrorOf<Self>>
        + TryFrom<
            CosmwasmCallInput<'x, PointerOf<Self>, InstantiateInput<VmMessageCustomOf<Self>>>,
            Error = VmErrorOf<Self>,
        > + TryFrom<
            CosmwasmCallInput<'x, PointerOf<Self>, ExecuteInput<VmMessageCustomOf<Self>>>,
            Error = VmErrorOf<Self>,
        > + TryFrom<
            CosmwasmCallInput<'x, PointerOf<Self>, ReplyInput<VmMessageCustomOf<Self>>>,
            Error = VmErrorOf<Self>,
        > + TryFrom<
            CosmwasmCallWithoutInfoInput<'x, PointerOf<Self>, ReplyInput<VmMessageCustomOf<Self>>>,
            Error = VmErrorOf<Self>,
        > + TryFrom<
            CosmwasmCallWithoutInfoInput<
                'x,
                PointerOf<Self>,
                MigrateInput<VmMessageCustomOf<Self>>,
            >,
            Error = VmErrorOf<Self>,
        > + TryFrom<CosmwasmCallInput<'x, PointerOf<Self>, I>, Error = VmErrorOf<Self>>
        + TryFrom<CosmwasmCallWithoutInfoInput<'x, PointerOf<Self>, I>, Error = VmErrorOf<Self>>,
    I: Input + HasInfo,
    OutputOf<I>: DeserializeOwned
        + ReadLimit
        + DeserializeLimit
        + Into<ContractResult<Response<VmMessageCustomOf<Self>>>>;

/// High level dispatch for a CosmWasm VM.
/// This call will manage and handle subcall as well as the transactions etc...
/// The implementation must be semantically valid w.r.t https://github.com/CosmWasm/cosmwasm/blob/main/SEMANTICS.md
///
/// Returns either the value produced by the contract along the generated events or a `VmErrorOf<V>`
pub fn cosmwasm_system_entrypoint<I, V>(
    vm: &mut V,
    message: &[u8],
) -> Result<(Option<Binary>, Vec<Event>), VmErrorOf<V>>
where
    V: CosmwasmCallVM<I>,
{
    log::debug!("SystemEntrypoint");
    let mut events = Vec::<Event>::new();
    let mut event_handler = |event: Event| {
        events.push(event);
    };
    vm.transaction_begin()?;
    match cosmwasm_system_run::<I, V>(vm, message, &mut event_handler) {
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

pub fn cosmwasm_system_run<I, V>(
    vm: &mut V,
    message: &[u8],
    mut event_handler: &mut dyn FnMut(Event),
) -> Result<Option<Binary>, VmErrorOf<V>>
where
    V: CosmwasmCallVM<I>,
{
    log::debug!("SystemRun");
    let info: MessageInfo = vm.get();
    let ensure_admin = move |contract_admin: &Option<String>| -> Result<(), VmErrorOf<V>> {
        let sender = info.sender.as_str();
        match contract_admin {
            None => Err(SystemError::ImmutableCantMigrate.into()),
            Some(admin) if admin.as_str() == sender => Ok(()),
            _ => Err(SystemError::MustBeAdmin.into()),
        }
    };
    let output = cosmwasm_call::<I, V>(vm, message).map(Into::into);
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
            if !attributes.is_empty() {
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
                 -> Result<Option<Binary>, VmErrorOf<V>> {
                    log::debug!("Executing submessages");
                    let mut sub_events = Vec::<Event>::new();
                    let mut sub_event_handler = |event: Event| {
                        event_handler(event.clone());
                        sub_events.push(event);
                    };
                    vm.transaction_begin()?;
                    vm.gas_checkpoint_push(match gas_limit {
                        Some(limit) => VmGasCheckpoint::Limited(limit),
                        None => VmGasCheckpoint::Unlimited,
                    })?;
                    let sub_res = match msg {
                        CosmosMsg::Custom(message) => vm
                            .message_custom(message, &mut event_handler)
                            .map_err(Into::into),
                        CosmosMsg::Wasm(wasm_message) => match wasm_message {
                            WasmMsg::Execute {
                                contract_addr,
                                msg: Binary(msg),
                                funds,
                            } => {
                                let vm_contract_addr = contract_addr.try_into()?;
                                vm.transfer(&vm_contract_addr, &funds)?;
                                vm.continue_execute(
                                    vm_contract_addr,
                                    vec![],
                                    &msg,
                                    &mut sub_event_handler,
                                )
                            }
                            WasmMsg::Instantiate {
                                admin,
                                code_id,
                                msg,
                                funds,
                                label,
                            } => {
                                let vm_contract_addr = vm.new_contract(CosmwasmContractMeta {
                                    code_id,
                                    admin,
                                    label,
                                })?;
                                vm.transfer(&vm_contract_addr, &funds)?;
                                vm.continue_instantiate(
                                    vm_contract_addr,
                                    funds,
                                    &msg,
                                    &mut sub_event_handler,
                                )
                            }
                            WasmMsg::Migrate {
                                contract_addr,
                                new_code_id,
                                msg: Binary(msg),
                            } => {
                                let vm_contract_addr = VmAddressOf::<V>::try_from(contract_addr)?;
                                let CosmwasmContractMeta { admin, label, .. } =
                                    vm.code_id(vm_contract_addr.clone())?;
                                ensure_admin(&admin)?;
                                vm.set_code_id(
                                    vm_contract_addr.clone(),
                                    CosmwasmContractMeta {
                                        code_id: new_code_id,
                                        admin,
                                        label,
                                    },
                                )?;
                                vm.continue_migrate(
                                    vm_contract_addr,
                                    vec![],
                                    &msg,
                                    &mut sub_event_handler,
                                )
                            }
                            WasmMsg::UpdateAdmin {
                                contract_addr,
                                admin: new_admin,
                            } => {
                                let vm_contract_addr = VmAddressOf::<V>::try_from(contract_addr)?;
                                let CosmwasmContractMeta {
                                    code_id,
                                    admin,
                                    label,
                                } = vm.code_id(vm_contract_addr.clone())?;
                                ensure_admin(&admin)?;
                                vm.set_code_id(
                                    vm_contract_addr,
                                    CosmwasmContractMeta {
                                        code_id,
                                        admin: Some(new_admin),
                                        label,
                                    },
                                )?;
                                Ok(None)
                            }
                            WasmMsg::ClearAdmin { contract_addr } => {
                                let vm_contract_addr = VmAddressOf::<V>::try_from(contract_addr)?;
                                let CosmwasmContractMeta {
                                    code_id,
                                    admin,
                                    label,
                                } = vm.code_id(vm_contract_addr.clone())?;
                                ensure_admin(&admin)?;
                                vm.set_code_id(
                                    vm_contract_addr,
                                    CosmwasmContractMeta {
                                        code_id,
                                        admin: None,
                                        label,
                                    },
                                )?;
                                Ok(None)
                            }
                        },
                        CosmosMsg::Bank(bank_message) => match bank_message {
                            BankMsg::Send { to_address, amount } => {
                                vm.transfer(&to_address.try_into()?, &amount)?;
                                Ok(None)
                            }
                            BankMsg::Burn { amount } => {
                                vm.burn(&amount)?;
                                Ok(None)
                            }
                        },
                    };

                    log::debug!("Submessage result: {:?}", sub_res);

                    vm.gas_checkpoint_pop()?;

                    let sub_cont = match (sub_res, reply_on) {
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
                        SubCallContinuation::Continue(v) => Ok(v.or(current)),
                        // Abort result in no value indeed.
                        SubCallContinuation::Abort(e) => Err(e),
                        // Might be overwritten again.
                        SubCallContinuation::Reply(response) => {
                            log::debug!("Replying");
                            let raw_response = serde_json::to_vec(&Reply {
                                id,
                                result: response,
                            })
                            .map_err(|_| SystemError::FailedToSerialize)?;
                            cosmwasm_system_run::<ReplyInput<VmMessageCustomOf<V>>, V>(
                                vm,
                                &raw_response,
                                &mut event_handler,
                            )
                            .map(|v| v.or(current))
                        }
                    }
                },
            )
        }
        Ok(ContractResult::Err(e)) => Err(SystemError::ContractExecutionFailure(e).into()),
        Err(e) => Err(e),
    }
}

/// High level query for a CosmWasm VM.
///
/// Returns either the value returned by the contract `query` export or a `VmErrorOf<V>`
pub fn cosmwasm_system_query<V>(
    vm: &mut V,
    request: QueryRequest<VmQueryCustomOf<V>>,
) -> Result<SystemResult<CosmwasmQueryResult>, VmErrorOf<V>>
where
    V: CosmwasmBaseVM,
{
    log::debug!("SystemQuery");
    match request {
        QueryRequest::Custom(query) => Ok(vm.query_custom(query)?),
        QueryRequest::Bank(bank_query) => match bank_query {
            BankQuery::Balance { address, denom } => {
                let vm_account_addr = address.try_into()?;
                let amount = vm.balance(&vm_account_addr, denom)?;
                let serialized_info = serde_json::to_vec(&BalanceResponse { amount })
                    .map_err(|_| SystemError::FailedToSerialize)?;
                Ok(SystemResult::Ok(ContractResult::Ok(Binary(
                    serialized_info,
                ))))
            }
            BankQuery::AllBalances { address } => {
                let vm_account_addr = address.try_into()?;
                let amount = vm.all_balance(&vm_account_addr)?;
                let serialized_info = serde_json::to_vec(&AllBalanceResponse { amount })
                    .map_err(|_| SystemError::FailedToSerialize)?;
                Ok(SystemResult::Ok(ContractResult::Ok(Binary(
                    serialized_info,
                ))))
            }
        },
        QueryRequest::Wasm(wasm_query) => match wasm_query {
            WasmQuery::Smart {
                contract_addr,
                msg: Binary(message),
            } => {
                let vm_contract_addr = contract_addr.try_into()?;
                let QueryResult(output) = vm.query_continuation(vm_contract_addr, &message)?;
                Ok(SystemResult::Ok(output))
            }
            WasmQuery::Raw {
                contract_addr,
                key: Binary(key),
            } => {
                let vm_contract_addr = contract_addr.try_into()?;
                let value = vm.query_raw(vm_contract_addr, key)?;
                Ok(SystemResult::Ok(ContractResult::Ok(Binary(
                    value.unwrap_or_default(),
                ))))
            }
            WasmQuery::ContractInfo { contract_addr } => {
                let vm_contract_addr = contract_addr.try_into()?;
                let info = vm.query_info(vm_contract_addr)?;
                let serialized_info =
                    serde_json::to_vec(&info).map_err(|_| SystemError::FailedToSerialize)?;
                Ok(SystemResult::Ok(ContractResult::Ok(Binary(
                    serialized_info,
                ))))
            }
        },
    }
}

/// High level query for a CosmWasm VM with remarshalling for contract execution continuation.
///
/// Returns either the JSON serialized value returned by the contract `query` export or a `VmErrorOf<V>`
pub fn cosmwasm_system_query_raw<V>(
    vm: &mut V,
    request: QueryRequest<VmQueryCustomOf<V>>,
) -> Result<Binary, VmErrorOf<V>>
where
    V: CosmwasmBaseVM,
{
    log::debug!("SystemQueryRaw");
    let output = cosmwasm_system_query(vm, request)?;
    Ok(Binary(
        serde_json::to_vec(&output).map_err(|_| SystemError::FailedToSerialize)?,
    ))
}
