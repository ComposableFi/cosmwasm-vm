// vm.rs ---

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

use crate::input::Input;
use alloc::{string::String, vec::Vec};
use core::fmt::Debug;
use cosmwasm_minimal_std::{
    Binary, Coin, ContractInfoResponse, CosmwasmQueryResult, Event, QueryResult, SystemResult,
};
use serde::de::DeserializeOwned;

pub enum VmGasCheckpoint {
    Unlimited,
    Limited(u64)
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VmGas {
    Instrumentation { metered: u32 },
    RawCall,
    NewContract,
    SetCodeId,
    GetCodeId,
    QueryContinuation,
    ContinueExecute,
    ContinueInstantiate,
    ContinueMigrate,
    QueryCustom,
    MessageCustom,
    QueryRaw,
    Transfer,
    Burn,
    Balance,
    AllBalance,
    QueryInfo,
    QueryChain,
    DbRead,
    DbWrite,
    DbRemove,
}

pub type VmInputOf<'a, T> = <T as VMBase>::Input<'a>;
pub type VmOutputOf<'a, T> = <T as VMBase>::Output<'a>;
pub type VmErrorOf<T> = <T as VMBase>::Error;
pub type VmQueryCustomOf<T> = <T as VMBase>::QueryCustom;
pub type VmMessageCustomOf<T> = <T as VMBase>::MessageCustom;
pub type VmAddressOf<T> = <T as VMBase>::Address;
pub type VmStorageKeyOf<T> = <T as VMBase>::StorageKey;
pub type VmStorageValueOf<T> = <T as VMBase>::StorageValue;
pub type VmCodeIdOf<T> = <T as VMBase>::CodeId;

pub trait VM: VMBase {
    fn call<'a, I>(&mut self, input: I) -> Result<I::Output, Self::Error>
    where
        I: Input + TryInto<VmInputOf<'a, Self>, Error = Self::Error>,
        I::Output: for<'x> TryFrom<VmOutputOf<'x, Self>, Error = Self::Error>,
    {
        let input = input.try_into()?;
        Ok(self.raw_call::<I::Output>(input)?)
    }

    fn raw_call<'a, O>(&mut self, input: Self::Input<'a>) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::Output<'x>, Error = Self::Error>;
}

pub trait VMBase {
    type Input<'a>;
    type Output<'a>;
    type QueryCustom: DeserializeOwned + Debug;
    type MessageCustom: DeserializeOwned + Debug;
    type CodeId;
    type Address;
    type StorageKey;
    type StorageValue;
    type Error;

    fn new_contract(&mut self, code_id: Self::CodeId) -> Result<Self::Address, Self::Error>;

    fn set_code_id(
        &mut self,
        address: Self::Address,
        new_code_id: Self::CodeId,
    ) -> Result<(), Self::Error>;

    fn code_id(&mut self, address: Self::Address) -> Result<Self::CodeId, Self::Error>;

    fn query_continuation(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<QueryResult, Self::Error>;

    fn continue_execute(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error>;

    fn continue_instantiate(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error>;

    fn continue_migrate(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error>;

    fn query_custom(
        &mut self,
        query: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, Self::Error>;

    fn message_custom(
        &mut self,
        message: Self::MessageCustom,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error>;

    fn query_raw(
        &mut self,
        address: Self::Address,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error>;

    /// Transfer `funds` from the current bank to `to`.
    fn transfer(&mut self, to: &Self::Address, funds: &[Coin]) -> Result<(), Self::Error>;

    /// Burn the `funds` from the current contract.
    fn burn(&mut self, funds: &[Coin]) -> Result<(), Self::Error>;

    /// Query the balance of `denom` tokens.
    fn balance(&self, account: &Self::Address, denom: String) -> Result<Coin, Self::Error>;

    /// Query for the balance of all tokens.
    fn all_balance(&self, account: &Self::Address) -> Result<Vec<Coin>, Self::Error>;

    fn query_info(&mut self, address: Self::Address) -> Result<ContractInfoResponse, Self::Error>;

    fn db_read(&mut self, key: Self::StorageKey)
        -> Result<Option<Self::StorageValue>, Self::Error>;

    fn db_write(
        &mut self,
        key: Self::StorageKey,
        value: Self::StorageValue,
    ) -> Result<(), Self::Error>;

    fn abort(&mut self, message: String) -> Result<(), Self::Error>;

    /// Charge gas value.
    fn charge(&mut self, value: VmGas) -> Result<(), Self::Error>;

    /// Push a gas checkpoint, used to trap once the checkpoint is reached.
    fn gas_checkpoint_push(&mut self, checkpoint: VmGasCheckpoint) -> Result<(), Self::Error>;

    /// Pop a previously pushed gas checkpoint.
    fn gas_checkpoint_pop(&mut self) -> Result<(), Self::Error>;

    /// Ensure that some gas is available.
    fn gas_ensure_available(&mut self) -> Result<(), Self::Error>;
}
