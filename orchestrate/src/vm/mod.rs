mod account;
mod address;
mod bank;
mod error;
mod state;

pub use account::*;
pub use address::*;
pub use error::*;
pub use state::*;

use super::ExecutionType;
use alloc::collections::BTreeMap;
use bank::Bank;
use core::{fmt::Debug, num::NonZeroU32};
use cosmwasm_std::{
    Binary, Coin, ContractInfo, ContractInfoResponse, Env, Event, IbcTimeout, MessageInfo, Order,
    Reply, SystemResult,
};
use cosmwasm_vm::{
    executor::{
        cosmwasm_call, CosmwasmQueryResult, ExecuteCall, InstantiateCall, MigrateCall, QueryCall,
        QueryResult, ReplyCall,
    },
    has::Has,
    memory::{Pointable, ReadWriteMemory, ReadableMemory, WritableMemory},
    system::{cosmwasm_system_run, CosmwasmContractMeta, SystemError},
    transaction::Transactional,
    vm::{VMBase, VmErrorOf, VmGas, VmGasCheckpoint},
};
use cosmwasm_vm_wasmi::{
    host_functions, new_wasmi_vm, WasmiContext, WasmiHost, WasmiHostFunction,
    WasmiHostFunctionIndex, WasmiImportResolver, WasmiInput, WasmiModule, WasmiOutput, WasmiVM,
    WasmiVMError,
};
use serde::de::DeserializeOwned;
use wasm_instrument::gas_metering::Rules;

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct Gas {
    pub checkpoints: Vec<u64>,
}

impl Gas {
    #[must_use]
    pub fn new(initial_value: u64) -> Self {
        Gas {
            checkpoints: vec![initial_value],
        }
    }

    #[must_use]
    pub fn current(&self) -> &u64 {
        self.checkpoints.last().expect("impossible")
    }

    pub fn current_mut(&mut self) -> &mut u64 {
        self.checkpoints.last_mut().expect("impossible")
    }

    pub fn push(&mut self, checkpoint: &VmGasCheckpoint) -> Result<(), VmError> {
        match checkpoint {
            VmGasCheckpoint::Unlimited => {
                let parent = self.current_mut();
                let value = *parent;
                *parent = 0;
                self.checkpoints.push(value);
                Ok(())
            }
            VmGasCheckpoint::Limited(limit) if limit <= self.current() => {
                *self.current_mut() -= limit;
                self.checkpoints.push(*limit);
                Ok(())
            }
            VmGasCheckpoint::Limited(_) => Err(VmError::OutOfGas),
        }
    }

    pub fn pop(&mut self) {
        let child = self.checkpoints.pop().expect("impossible");
        let parent = self.current_mut();
        *parent += child;
    }

    pub fn charge(&mut self, value: u64) -> Result<(), VmError> {
        let current = self.current_mut();
        if *current >= value {
            *current -= value;
            Ok(())
        } else {
            Err(VmError::OutOfGas)
        }
    }
}

pub type QueryCustomOf<T> = <T as CustomHandler>::QueryCustom;
pub type MessageCustomOf<T> = <T as CustomHandler>::MessageCustom;

pub trait CustomHandler: Sized + Clone + Default {
    type QueryCustom: DeserializeOwned + Debug;
    type MessageCustom: DeserializeOwned + Debug;

    fn handle_message<AH: AddressHandler>(
        vm: &mut Context<Self, AH>,
        message: Self::MessageCustom,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, VmError>;

    fn handle_query<AH: AddressHandler>(
        vm: &mut Context<Self, AH>,
        query: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, VmError>;
}

impl CustomHandler for () {
    type QueryCustom = ();
    type MessageCustom = ();

    fn handle_message<AH: AddressHandler>(
        _: &mut Context<Self, AH>,
        _: Self::MessageCustom,
        _: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, VmError> {
        Err(VmError::NoCustomMessage)
    }

    fn handle_query<AH: AddressHandler>(
        _: &mut Context<Self, AH>,
        _: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, VmError> {
        Err(VmError::NoCustomQuery)
    }
}

#[derive(Default, Clone, Debug)]
pub struct Iter {
    pub data: Vec<(Vec<u8>, Vec<u8>)>,
    pub position: usize,
}

#[derive(Default, Clone, Debug)]
pub struct Storage {
    pub data: BTreeMap<Vec<u8>, Vec<u8>>,
    pub iterators: BTreeMap<u32, Iter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IbcPacket {
    pub data: Binary,
    pub timeout: IbcTimeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IbcTransfer {
    pub to_address: String,
    pub amount: Coin,
    pub timeout: IbcTimeout,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct IbcState {
    pub packets: Vec<IbcPacket>,
    pub transfers: Vec<IbcTransfer>,
    pub request_close: bool,
}

impl IbcState {
    pub fn clear(&mut self) {
        self.packets.clear();
        self.transfers.clear();
        self.request_close = false;
    }
}

pub type IbcChannelId = String;

#[derive(Default, Clone)]
pub struct Db<CH> {
    pub ibc: BTreeMap<IbcChannelId, IbcState>,
    pub contracts: BTreeMap<Account, CosmwasmContractMeta<Account>>,
    pub storage: BTreeMap<Account, Storage>,
    pub bank: Bank,
    pub custom_handler: CH,
}

impl<CH: CustomHandler> Debug for Db<CH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Db")
            .field("ibc", &self.ibc)
            .field("contracts", &self.contracts)
            .field("bank", &self.bank)
            .finish()
    }
}

pub struct Context<'a, CH: CustomHandler, AH: AddressHandler> {
    pub host_functions: BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<Self>>,
    pub executing_module: WasmiModule,
    pub env: Env,
    pub info: MessageInfo,
    pub state: &'a mut State<CH, AH>,
}

impl<'a, CH: CustomHandler, AH: AddressHandler> WasmiContext for Context<'a, CH, AH> {
    fn executing_module(&self) -> WasmiModule {
        self.executing_module.clone()
    }
}

impl<'a, CH: CustomHandler, AH: AddressHandler> WasmiHost<Self> for Context<'a, CH, AH> {
    fn host_function(&self, index: WasmiHostFunctionIndex) -> Option<&WasmiHostFunction<Self>> {
        self.host_functions.get(&index)
    }
}

impl<'a, CH: CustomHandler, AH: AddressHandler> Pointable for Context<'a, CH, AH> {
    type Pointer = u32;
}

impl<'a, CH: CustomHandler, AH: AddressHandler> ReadableMemory for Context<'a, CH, AH> {
    type Error = VmErrorOf<Self>;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.executing_module
            .memory
            .get_into(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryReadError.into())
    }
}

impl<'a, CH: CustomHandler, AH: AddressHandler> WritableMemory for Context<'a, CH, AH> {
    type Error = VmErrorOf<Self>;
    fn write(&self, offset: Self::Pointer, buffer: &[u8]) -> Result<(), Self::Error> {
        self.executing_module
            .memory
            .set(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryWriteError.into())
    }
}

impl<'a, CH: CustomHandler, AH: AddressHandler> ReadWriteMemory for Context<'a, CH, AH> {}

impl<'a, CH: CustomHandler, AH: AddressHandler> Context<'a, CH, AH> {
    fn load_subvm<R>(
        &mut self,
        address: <Self as VMBase>::Address,
        funds: Vec<Coin>,
        f: impl FnOnce(&mut WasmiVM<Context<CH, AH>>) -> R,
    ) -> Result<R, VmErrorOf<Self>> {
        log::debug!(
            "Loading sub-vm {:?} => {:?}",
            self.env.contract.address,
            address
        );
        let CosmwasmContractMeta { code_id, .. } =
            self.state
                .db
                .contracts
                .get(&address)
                .cloned()
                .ok_or_else(|| VmError::ContractNotFound(address.clone()))?;
        let code = self
            .state
            .codes
            .get(&code_id)
            .ok_or(VmError::CodeNotFound(code_id))
            .cloned()?;
        let host_functions_definitions =
            WasmiImportResolver(host_functions::definitions::<Context<CH, AH>>());
        let module = new_wasmi_vm(&host_functions_definitions, &code.1)?;
        let mut sub_vm: WasmiVM<Context<CH, AH>> = WasmiVM(Context {
            host_functions: host_functions_definitions
                .0
                .into_iter()
                .flat_map(|(_, modules)| modules.into_values())
                .collect(),
            executing_module: module,
            env: Env {
                block: self.env.block.clone(),
                transaction: self.env.transaction.clone(),
                contract: ContractInfo {
                    address: address.into(),
                },
            },
            info: MessageInfo {
                sender: self.env.contract.address.clone(),
                funds,
            },
            state: self.state,
        });
        Ok(f(&mut sub_vm))
    }
}

impl<'a, CH: CustomHandler, AH: AddressHandler> VMBase for Context<'a, CH, AH> {
    type Input<'x> = WasmiInput<'x, WasmiVM<Self>>;
    type Output<'x> = WasmiOutput<'x, WasmiVM<Self>>;
    type QueryCustom = QueryCustomOf<CH>;
    type MessageCustom = MessageCustomOf<CH>;
    type ContractMeta = CosmwasmContractMeta<Account>;
    type Address = Account;
    type CanonicalAddress = CanonicalAccount;
    type StorageKey = Vec<u8>;
    type StorageValue = Vec<u8>;
    type Error = VmError;

    fn running_contract_meta(&mut self) -> Result<Self::ContractMeta, Self::Error> {
        Ok(self
            .state
            .db
            .contracts
            .get(&Account::try_from(self.env.contract.address.clone()).expect("impossible"))
            .cloned()
            .expect("contract is inserted by vm, this should never happen"))
    }

    fn set_contract_meta(
        &mut self,
        address: Self::Address,
        contract_meta: Self::ContractMeta,
    ) -> Result<(), Self::Error> {
        let meta = self
            .state
            .db
            .contracts
            .get_mut(&address)
            .ok_or(VmError::ContractNotFound(address))?;

        *meta = contract_meta;

        Ok(())
    }

    fn contract_meta(&mut self, address: Self::Address) -> Result<Self::ContractMeta, Self::Error> {
        self.state
            .db
            .contracts
            .get_mut(&address)
            .ok_or(VmError::ContractNotFound(address))
            .cloned()
    }

    fn continue_query(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<QueryResult, Self::Error> {
        self.load_subvm(address, vec![], |sub_vm| {
            cosmwasm_call::<QueryCall, WasmiVM<Context<CH, AH>>>(sub_vm, message)
        })?
    }

    fn continue_execute(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        log::debug!(
            "Continue Execute {:?} => {:?}",
            self.env.contract.address,
            address
        );
        self.load_subvm(address, funds, |sub_vm| {
            cosmwasm_system_run::<ExecuteCall<Self::MessageCustom>, _>(
                sub_vm,
                message,
                event_handler,
            )
        })?
    }

    fn continue_instantiate(
        &mut self,
        contract_meta: Self::ContractMeta,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<(Self::Address, Option<Binary>), Self::Error> {
        let (_, code_hash) = &self
            .state
            .codes
            .get(&contract_meta.code_id)
            .ok_or(VmError::CodeNotFound(contract_meta.code_id))?;
        let address = Account::generate::<AH>(code_hash, message)?;

        self.state
            .db
            .contracts
            .insert(address.clone(), contract_meta);

        self.load_subvm(address.clone(), funds, |sub_vm| {
            cosmwasm_system_run::<InstantiateCall<Self::MessageCustom>, _>(
                sub_vm,
                message,
                event_handler,
            )
        })?
        .map(|data| (address, data))
    }

    fn continue_migrate(
        &mut self,
        address: Self::Address,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.load_subvm(address, vec![], |sub_vm| {
            cosmwasm_system_run::<MigrateCall<Self::MessageCustom>, _>(
                sub_vm,
                message,
                event_handler,
            )
        })?
    }

    fn continue_reply(
        &mut self,
        message: Reply,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.load_subvm(
            self.env.contract.address.clone().into_string().try_into()?,
            vec![],
            |sub_vm| {
                cosmwasm_system_run::<ReplyCall<Self::MessageCustom>, _>(
                    sub_vm,
                    &serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?,
                    event_handler,
                )
            },
        )?
    }

    fn query_custom(
        &mut self,
        query: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, Self::Error> {
        CH::handle_query(self, query)
    }

    fn message_custom(
        &mut self,
        message: Self::MessageCustom,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        CH::handle_message(self, message, event_handler)
    }

    fn query_raw(
        &mut self,
        address: Self::Address,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error> {
        Ok(self
            .state
            .db
            .storage
            .get(&address)
            .unwrap_or(&Storage::default())
            .data
            .get(&key)
            .cloned())
    }

    fn transfer_from(
        &mut self,
        from: &Self::Address,
        to: &Self::Address,
        funds: &[Coin],
    ) -> Result<(), Self::Error> {
        log::debug!("Transfer: {:?} -> {:?}\n{:?}", from, to, funds);
        self.state
            .db
            .bank
            .transfer(from, to, funds)
            .map_err(Into::into)
    }

    fn transfer(&mut self, to: &Self::Address, funds: &[Coin]) -> Result<(), Self::Error> {
        let account = self.env.contract.address.clone().try_into()?;
        self.transfer_from(&account, to, funds)
    }

    fn burn(&mut self, funds: &[Coin]) -> Result<(), Self::Error> {
        log::debug!("Burn: {:?}\n{:?}", self.env.contract.address, funds);
        self.state
            .db
            .bank
            .burn(&self.env.contract.address.clone().try_into()?, funds)
            .map_err(Into::into)
    }

    fn balance(&mut self, account: &Self::Address, denom: String) -> Result<Coin, Self::Error> {
        log::debug!("Query balance.");
        Ok(Coin::new(
            self.state.db.bank.balance(account, &denom),
            denom,
        ))
    }

    fn all_balance(&mut self, account: &Self::Address) -> Result<Vec<Coin>, Self::Error> {
        log::debug!("Query all balance.");
        Ok(self.state.db.bank.all_balances(account))
    }

    fn query_info(&mut self, _: Self::Address) -> Result<ContractInfoResponse, Self::Error> {
        Err(VmError::Unsupported)
    }

    fn debug(&mut self, message: Vec<u8>) -> Result<(), Self::Error> {
        log::info!("[contract-debug] {}", String::from_utf8_lossy(&message));
        Ok(())
    }

    fn db_scan(
        &mut self,
        _start: Option<Self::StorageKey>,
        _end: Option<Self::StorageKey>,
        _order: Order,
    ) -> Result<u32, Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        let mut empty = Storage::default();
        let storage = self
            .state
            .db
            .storage
            .get_mut(&contract_addr)
            .unwrap_or(&mut empty);

        let data = storage.data.clone().into_iter().collect::<Vec<_>>();
        // Exceeding u32 size is fatal
        let last_id: u32 = storage
            .iterators
            .len()
            .try_into()
            .expect("Found more iterator IDs than supported");

        let new_id = last_id + 1;
        let iter = Iter { data, position: 0 };
        storage.iterators.insert(new_id, iter);

        Ok(new_id)
    }

    fn db_next(
        &mut self,
        iterator_id: u32,
    ) -> Result<(Self::StorageKey, Self::StorageValue), Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        let storage = self
            .state
            .db
            .storage
            .get_mut(&contract_addr)
            .ok_or(VmError::IteratorDoesNotExist)?;

        let iterator = storage
            .iterators
            .get_mut(&iterator_id)
            .ok_or(VmError::IteratorDoesNotExist)?;

        let position = iterator.position;
        if iterator.data.len() > position {
            iterator.position += 1;
            Ok(iterator.data[position].clone())
        } else {
            // Empty data works like `None` in rust iterators
            Ok((Vec::default(), Vec::default()))
        }
    }

    fn secp256k1_verify(
        &mut self,
        message_hash: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Self::Error> {
        cosmwasm_crypto::secp256k1_verify(message_hash, signature, public_key)
            .map_err(|_| VmError::CryptoError)
    }

    fn secp256k1_recover_pubkey(
        &mut self,
        message_hash: &[u8],
        signature: &[u8],
        recovery_param: u8,
    ) -> Result<Result<Vec<u8>, ()>, Self::Error> {
        Ok(
            cosmwasm_crypto::secp256k1_recover_pubkey(message_hash, signature, recovery_param)
                .map_err(|_| ()),
        )
    }

    fn ed25519_verify(
        &mut self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Self::Error> {
        cosmwasm_crypto::ed25519_verify(message, signature, public_key)
            .map_err(|_| VmError::CryptoError)
    }

    fn ed25519_batch_verify(
        &mut self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<bool, Self::Error> {
        cosmwasm_crypto::ed25519_batch_verify(messages, signatures, public_keys)
            .map_err(|_| VmError::CryptoError)
    }

    fn addr_validate(&mut self, input: &str) -> Result<Result<(), Self::Error>, Self::Error> {
        Ok(AH::addr_validate(input))
    }

    fn addr_canonicalize(
        &mut self,
        input: &str,
    ) -> Result<Result<Self::CanonicalAddress, Self::Error>, Self::Error> {
        match AH::addr_canonicalize(input) {
            Ok(canonical) => Ok(canonical.try_into()),
            Err(e) => Ok(Err(e)),
        }
    }

    fn addr_humanize(
        &mut self,
        addr: &Self::CanonicalAddress,
    ) -> Result<Result<Self::Address, Self::Error>, Self::Error> {
        match AH::addr_humanize(addr.0.as_ref()) {
            Ok(addr) => Ok(addr.try_into()),
            Err(e) => Ok(Err(e)),
        }
    }

    fn db_read(
        &mut self,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        let empty = Storage::default();
        Ok(self
            .state
            .db
            .storage
            .get(&contract_addr)
            .unwrap_or(&empty)
            .data
            .get(&key)
            .cloned())
    }

    fn db_write(
        &mut self,
        key: Self::StorageKey,
        value: Self::StorageValue,
    ) -> Result<(), Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        self.state
            .db
            .storage
            .entry(contract_addr)
            .or_insert_with(Storage::default)
            .data
            .insert(key, value);
        Ok(())
    }

    fn db_remove(&mut self, key: Self::StorageKey) -> Result<(), Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        self.state
            .db
            .storage
            .get_mut(&contract_addr)
            .map(|contract_storage| contract_storage.data.remove(&key));
        Ok(())
    }

    fn abort(&mut self, message: String) -> Result<(), Self::Error> {
        log::debug!("Contract aborted: {}", message);
        Err(VmError::from(WasmiVMError::from(
            SystemError::ContractExecutionFailure(message),
        )))
    }

    fn charge(&mut self, value: VmGas) -> Result<(), Self::Error> {
        let gas_to_charge = match value {
            VmGas::Instrumentation { metered } => u64::from(metered),
            x => {
                log::debug!("Charging gas: {:?}", x);
                1u64
            }
        };
        self.state.gas.charge(gas_to_charge)?;
        Ok(())
    }

    fn gas_checkpoint_push(&mut self, checkpoint: VmGasCheckpoint) -> Result<(), Self::Error> {
        log::debug!("> Gas before: {:?}", self.state.gas);
        self.state.gas.push(&checkpoint)?;
        log::debug!("> Gas after: {:?}", self.state.gas);
        Ok(())
    }

    fn gas_checkpoint_pop(&mut self) -> Result<(), Self::Error> {
        log::debug!("> Gas before: {:?}", self.state.gas);
        self.state.gas.pop();
        log::debug!("> Gas after: {:?}", self.state.gas);
        Ok(())
    }

    fn gas_ensure_available(&mut self) -> Result<(), Self::Error> {
        let checkpoint = self
            .state
            .gas
            .checkpoints
            .last()
            .expect("invalis gas checkpoint state");
        if *checkpoint > 0 {
            Ok(())
        } else {
            Err(VmError::OutOfGas)
        }
    }

    fn ibc_transfer(
        &mut self,
        channel_id: String,
        to_address: String,
        amount: Coin,
        timeout: IbcTimeout,
    ) -> Result<(), Self::Error> {
        match self.state.db.ibc.get_mut(&channel_id) {
            Some(channel) => {
                channel.transfers.push(IbcTransfer {
                    to_address,
                    amount,
                    timeout,
                });
                Ok(())
            }
            None => Err(VmError::UnknownIbcChannel),
        }
    }

    fn ibc_send_packet(
        &mut self,
        channel_id: String,
        data: Binary,
        timeout: IbcTimeout,
    ) -> Result<(), Self::Error> {
        match self.state.db.ibc.get_mut(&channel_id) {
            Some(channel) => {
                channel.packets.push(IbcPacket { data, timeout });
                Ok(())
            }
            None => Err(VmError::UnknownIbcChannel),
        }
    }

    fn ibc_close_channel(&mut self, channel_id: String) -> Result<(), Self::Error> {
        match self.state.db.ibc.get_mut(&channel_id) {
            Some(channel) => {
                channel.request_close = true;
                Ok(())
            }
            None => Err(VmError::UnknownIbcChannel),
        }
    }
}

impl<'a, CH: CustomHandler, AH: AddressHandler> Has<Env> for Context<'a, CH, AH> {
    fn get(&self) -> Env {
        self.env.clone()
    }
}
impl<'a, CH: CustomHandler, AH: AddressHandler> Has<MessageInfo> for Context<'a, CH, AH> {
    fn get(&self) -> MessageInfo {
        self.info.clone()
    }
}

impl<'a, CH: CustomHandler, AH: AddressHandler> Transactional for Context<'a, CH, AH> {
    type Error = VmError;
    fn transaction_begin(&mut self) -> Result<(), Self::Error> {
        self.state.transactions.push_back(self.state.db.clone());
        log::debug!("> Transaction begin: {}", self.state.transactions.len());
        Ok(())
    }
    fn transaction_commit(&mut self) -> Result<(), Self::Error> {
        let _ = self.state.transactions.pop_back().expect("impossible");
        log::debug!("< Transaction commit: {}", self.state.transactions.len());
        Ok(())
    }
    fn transaction_rollback(&mut self) -> Result<(), Self::Error> {
        self.state.db = self.state.transactions.pop_back().expect("impossible");
        log::debug!("< Transaction abort: {}", self.state.transactions.len());
        Ok(())
    }
}

struct ConstantCostRules;
impl Rules for ConstantCostRules {
    fn instruction_cost(
        &self,
        _: &wasm_instrument::parity_wasm::elements::Instruction,
    ) -> Option<u32> {
        Some(42)
    }

    fn memory_grow_cost(&self) -> wasm_instrument::gas_metering::MemoryGrowCost {
        wasm_instrument::gas_metering::MemoryGrowCost::Linear(
            NonZeroU32::new(1024).expect("impossible"),
        )
    }
}
