mod account;
pub mod cw20_ics20;
mod error;

pub use account::*;
use alloc::{
    collections::{BTreeMap, VecDeque},
    string::ToString,
};
use core::num::NonZeroU32;
use cosmwasm_std::{
    Binary, Coin, ContractInfo, ContractInfoResponse, Empty, Env, Event, IbcTimeout, MessageInfo,
    Order, SystemResult,
};
use cosmwasm_vm::{
    executor::{
        cosmwasm_call, CosmwasmQueryResult, ExecuteInput, InstantiateInput, MigrateInput,
        QueryInput, QueryResult,
    },
    has::Has,
    memory::{Pointable, ReadWriteMemory, ReadableMemory, WritableMemory},
    system::{cosmwasm_system_run, CosmwasmCodeId, CosmwasmContractMeta, SystemError},
    transaction::Transactional,
    vm::{VMBase, VmErrorOf, VmGas, VmGasCheckpoint},
};
use cosmwasm_vm_wasmi::{
    host_functions, new_wasmi_vm, WasmiHostFunction, WasmiHostFunctionIndex, WasmiImportResolver,
    WasmiInput, WasmiModule, WasmiModuleExecutor, WasmiOutput, WasmiVM, WasmiVMError,
};
pub use error::*;
use sha2::{Digest, Sha256};
use wasm_instrument::gas_metering::Rules;

const CANONICAL_LENGTH: usize = 54;
const SHUFFLES_ENCODE: usize = 18;
const SHUFFLES_DECODE: usize = 2;

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct Gas {
    pub checkpoints: Vec<u64>,
}

impl Gas {
    pub fn new(initial_value: u64) -> Self {
        Gas {
            checkpoints: vec![initial_value],
        }
    }

    pub fn current(&self) -> &u64 {
        self.checkpoints.last().expect("impossible")
    }

    pub fn current_mut(&mut self) -> &mut u64 {
        self.checkpoints.last_mut().expect("impossible")
    }

    pub fn push(&mut self, checkpoint: VmGasCheckpoint) -> Result<(), VmError> {
        match checkpoint {
            VmGasCheckpoint::Unlimited => {
                let parent = self.current_mut();
                let value = *parent;
                *parent = 0;
                self.checkpoints.push(value);
                Ok(())
            }
            VmGasCheckpoint::Limited(limit) if limit <= *self.current() => {
                *self.current_mut() -= limit;
                self.checkpoints.push(limit);
                Ok(())
            }
            _ => Err(VmError::OutOfGas),
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
pub struct Db {
    pub ibc: BTreeMap<(Account, IbcChannelId), IbcState>,
    pub contracts: BTreeMap<Account, CosmwasmContractMeta<Account>>,
    pub storage: BTreeMap<Account, Storage>,
}

#[derive(Default, Clone)]
pub struct State {
    pub transactions: VecDeque<Db>,
    pub db: Db,
    pub codes: BTreeMap<CosmwasmCodeId, (Vec<u8>, Vec<u8>)>,
    pub gas: Gas,
}

pub struct Context<'a> {
    pub host_functions: BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<Self>>,
    pub executing_module: WasmiModule,
    pub env: Env,
    pub info: MessageInfo,
    pub state: &'a mut State,
}

impl<'a> WasmiModuleExecutor for Context<'a> {
    fn executing_module(&self) -> WasmiModule {
        self.executing_module.clone()
    }
    fn host_function(&self, index: WasmiHostFunctionIndex) -> Option<&WasmiHostFunction<Self>> {
        self.host_functions.get(&index)
    }
}

impl<'a> Pointable for Context<'a> {
    type Pointer = u32;
}

impl<'a> ReadableMemory for Context<'a> {
    type Error = VmErrorOf<Self>;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.executing_module
            .memory
            .get_into(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryReadError.into())
    }
}

impl<'a> WritableMemory for Context<'a> {
    type Error = VmErrorOf<Self>;
    fn write(&self, offset: Self::Pointer, buffer: &[u8]) -> Result<(), Self::Error> {
        self.executing_module
            .memory
            .set(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryWriteError.into())
    }
}

impl<'a> ReadWriteMemory for Context<'a> {}

impl<'a> Context<'a> {
    fn load_subvm<R>(
        &mut self,
        address: <Self as VMBase>::Address,
        funds: Vec<Coin>,
        f: impl FnOnce(&mut WasmiVM<Context>) -> R,
    ) -> Result<R, VmErrorOf<Self>> {
        log::debug!("Loading sub-vm, contract address: {:?}", address);
        let code = (|| {
            let CosmwasmContractMeta { code_id, .. } = self
                .state
                .db
                .contracts
                .get(&address)
                .cloned()
                .ok_or_else(|| VmError::ContractNotFound(address.clone()))?;
            self.state
                .codes
                .get(&code_id)
                .ok_or(VmError::CodeNotFound(code_id))
                .cloned()
        })()?;
        let host_functions_definitions =
            WasmiImportResolver(host_functions::definitions::<Context>());
        let module = new_wasmi_vm(&host_functions_definitions, &code.1)?;
        let mut sub_vm: WasmiVM<Context> = WasmiVM(Context {
            host_functions: host_functions_definitions
                .0
                .into_iter()
                .flat_map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
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

impl<'a> VMBase for Context<'a> {
    type Input<'x> = WasmiInput<'x, WasmiVM<Self>>;
    type Output<'x> = WasmiOutput<'x, WasmiVM<Self>>;
    type QueryCustom = Empty;
    type MessageCustom = Empty;
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

    fn query_continuation(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<QueryResult, Self::Error> {
        self.load_subvm(address, vec![], |sub_vm| {
            cosmwasm_call::<QueryInput, WasmiVM<Context>>(sub_vm, message)
        })?
    }

    fn continue_execute(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        self.load_subvm(address, funds, |sub_vm| {
            cosmwasm_system_run::<ExecuteInput<Self::MessageCustom>, _>(
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
        let address = Account::generate(
            &self
                .state
                .codes
                .get(&contract_meta.code_id)
                .ok_or(VmError::CodeNotFound(contract_meta.code_id))?
                .1,
            message,
        );
        self.state
            .db
            .contracts
            .insert(address.clone(), contract_meta);

        self.load_subvm(address.clone(), funds, |sub_vm| {
            cosmwasm_system_run::<InstantiateInput<Self::MessageCustom>, _>(
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
            cosmwasm_system_run::<MigrateInput<Self::MessageCustom>, _>(
                sub_vm,
                message,
                event_handler,
            )
        })?
    }

    fn query_custom(
        &mut self,
        _: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, Self::Error> {
        Err(VmError::NoCustomQuery)
    }

    fn message_custom(
        &mut self,
        _: Self::MessageCustom,
        _: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        Err(VmError::NoCustomMessage)
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
            .unwrap_or(&Default::default())
            .data
            .get(&key)
            .cloned())
    }

    fn transfer(&mut self, to: &Self::Address, funds: &[Coin]) -> Result<(), Self::Error> {
        log::debug!(
            "Transfer: {:?} -> {:?}\n{:?}",
            self.env.contract.address,
            to,
            funds
        );
        Err(VmError::Unsupported)
    }

    fn burn(&mut self, funds: &[Coin]) -> Result<(), Self::Error> {
        log::debug!("Burn: {:?}\n{:?}", self.env.contract.address, funds);
        Err(VmError::Unsupported)
    }

    fn balance(&mut self, _: &Self::Address, _: String) -> Result<Coin, Self::Error> {
        log::debug!("Query balance.");
        Err(VmError::Unsupported)
    }

    fn all_balance(&mut self, _: &Self::Address) -> Result<Vec<Coin>, Self::Error> {
        log::debug!("Query all balance.");
        Err(VmError::Unsupported)
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
            Ok((Default::default(), Default::default()))
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
        let canonical = match self.addr_canonicalize(input)? {
            Ok(canonical) => canonical,
            Err(e) => return Ok(Err(e)),
        };
        let normalized = match self.addr_humanize(&canonical)? {
            Ok(canonical) => canonical,
            Err(e) => return Ok(Err(e)),
        };
        let account = Account::try_from(input.to_string())?;
        if account != normalized {
            Ok(Err(VmError::InvalidAddress))
        } else {
            Ok(Ok(()))
        }
    }

    fn addr_canonicalize(
        &mut self,
        input: &str,
    ) -> Result<Result<Self::CanonicalAddress, Self::Error>, Self::Error> {
        // mimicks formats like hex or bech32 where different casings are valid for one address
        let normalized = input.to_lowercase();

        // Dummy input validation. This is more sophisticated for formats like bech32, where format and checksum are validated.
        if normalized.len() < 3 {
            return Ok(Err(VmError::InvalidAddress));
        }

        if normalized.len() > CANONICAL_LENGTH {
            return Ok(Err(VmError::InvalidAddress));
        }

        let mut out = Vec::from(normalized);
        // pad to canonical length with NULL bytes
        out.resize(CANONICAL_LENGTH, 0x00);
        // content-dependent rotate followed by shuffle to destroy
        let rotate_by = digit_sum(&out) % CANONICAL_LENGTH;
        out.rotate_left(rotate_by);
        for _ in 0..SHUFFLES_ENCODE {
            out = riffle_shuffle(&out);
        }
        Ok(Ok(out.try_into()?))
    }

    fn addr_humanize(
        &mut self,
        addr: &Self::CanonicalAddress,
    ) -> Result<Result<Self::Address, Self::Error>, Self::Error> {
        if addr.0.len() != CANONICAL_LENGTH {
            return Ok(Err(VmError::InvalidAddress));
        }

        let mut tmp: Vec<u8> = addr.clone().into();
        // Shuffle two more times which restored the original value (24 elements are back to original after 20 rounds)
        for _ in 0..SHUFFLES_DECODE {
            tmp = riffle_shuffle(&tmp);
        }
        // Rotate back
        let rotate_by = digit_sum(&tmp) % CANONICAL_LENGTH;
        tmp.rotate_right(rotate_by);
        // Remove NULL bytes (i.e. the padding)
        let trimmed = tmp.into_iter().filter(|&x| x != 0x00).collect();
        // decode UTF-8 bytes into string
        let human = match String::from_utf8(trimmed) {
            Ok(trimmed) => trimmed,
            Err(_) => return Ok(Err(VmError::InvalidAddress)),
        };
        Ok(Account::try_from(human).map_err(|_| VmError::InvalidAddress))
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
            VmGas::Instrumentation { metered } => metered as u64,
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
        self.state.gas.push(checkpoint)?;
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
        let contract_addr = self.env.contract.address.clone().try_into()?;
        match self.state.db.ibc.get_mut(&(contract_addr, channel_id)) {
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
        let contract_addr = self.env.contract.address.clone().try_into()?;
        match self.state.db.ibc.get_mut(&(contract_addr, channel_id)) {
            Some(channel) => {
                channel.packets.push(IbcPacket { data, timeout });
                Ok(())
            },
            None => Err(VmError::UnknownIbcChannel),
        }
    }

    fn ibc_close_channel(&mut self, channel_id: String) -> Result<(), Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        match self.state.db.ibc.get_mut(&(contract_addr, channel_id)) {
            Some(channel) => {
                channel.request_close = true;
                Ok(())
            }
            None => Err(VmError::UnknownIbcChannel),
        }
    }
}

impl<'a> Has<Env> for Context<'a> {
    fn get(&self) -> Env {
        self.env.clone()
    }
}
impl<'a> Has<MessageInfo> for Context<'a> {
    fn get(&self) -> MessageInfo {
        self.info.clone()
    }
}

impl<'a> Transactional for Context<'a> {
    type Error = VmError;
    fn transaction_begin(&mut self) -> Result<(), Self::Error> {
        self.state.transactions.push_back(self.state.db.clone());
        log::debug!("> Transaction begin: {}", self.state.transactions.len());
        Ok(())
    }
    fn transaction_commit(&mut self) -> Result<(), Self::Error> {
        let _ = self.state.transactions.pop_back().expect("impossible");
        log::debug!("< Transaction end: {}", self.state.transactions.len());
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

pub(crate) fn create_vm(extension: &mut State, env: Env, info: MessageInfo) -> WasmiVM<Context> {
    let code = extension
        .codes
        .get(
            &extension
                .db
                .contracts
                .get(
                    &env.clone()
                        .contract
                        .address
                        .try_into()
                        .expect("Invalid address"),
                )
                .expect("contract should have been uploaded")
                .code_id,
        )
        .expect("contract should have been uploaded");
    let host_functions_definitions = WasmiImportResolver(host_functions::definitions());
    let module = new_wasmi_vm(&host_functions_definitions, &code.1).unwrap();
    WasmiVM(Context {
        host_functions: host_functions_definitions
            .0
            .clone()
            .into_iter()
            .flat_map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
            .collect(),
        executing_module: module,
        env,
        info,
        state: extension,
    })
}

impl State {
    pub fn with_codes(codes: Vec<&[u8]>) -> Self {
        let mut code_id = 0;
        Self {
            codes: BTreeMap::from_iter(codes.into_iter().map(|code| {
                code_id += 1;
                let code_hash: Vec<u8> = Sha256::new().chain_update(code).finalize()[..].into();
                (code_id, (code_hash, code.into()))
            })),
            gas: Gas::new(100_000_000),
            ..Default::default()
        }
    }
}

fn digit_sum(input: &[u8]) -> usize {
    input.iter().fold(0, |sum, val| sum + (*val as usize))
}

fn riffle_shuffle<T: Clone>(input: &[T]) -> Vec<T> {
    assert!(
        input.len() % 2 == 0,
        "Method only defined for even number of elements"
    );
    let mid = input.len() / 2;
    let (left, right) = input.split_at(mid);
    let mut out = Vec::<T>::with_capacity(input.len());
    for i in 0..mid {
        out.push(right[i].clone());
        out.push(left[i].clone());
    }
    out
}
