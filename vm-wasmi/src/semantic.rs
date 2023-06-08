extern crate std;

use crate::version::{Version, Version1x};

use super::{
    code_gen, new_wasmi_vm, OwnedWasmiVM, VMBase, WasmiContext, WasmiInput, WasmiModule,
    WasmiOutput, WasmiVMError,
};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{
    assert_matches::assert_matches,
    fmt::{Debug, Display},
    num::NonZeroU32,
    str::FromStr,
};
#[cfg(feature = "stargate")]
use cosmwasm_std::IbcTimeout;
#[cfg(feature = "iterator")]
use cosmwasm_std::Order;
use cosmwasm_std::{
    Addr, Attribute, Binary, BlockInfo, CanonicalAddr, CodeInfoResponse, Coin, ContractInfo,
    ContractInfoResponse, ContractResult, Empty, Env, Event, MessageInfo, Reply, SystemResult,
    Timestamp,
};
use cosmwasm_vm::{
    executor::{
        cosmwasm_call, CosmwasmExecutionResult, CosmwasmQueryResult, ExecuteCall, ExecuteResult,
        ExecutorError, InstantiateCall, InstantiateResult, MigrateCall, QueryCall, QueryResult,
        ReplyCall,
    },
    has::Has,
    memory::{MemoryReadError, MemoryWriteError},
    system::{
        cosmwasm_system_entrypoint, cosmwasm_system_entrypoint_hook, cosmwasm_system_run,
        CosmwasmCodeId, CosmwasmContractMeta, SystemError,
    },
    transaction::Transactional,
    vm::{VmErrorOf, VmGas, VmGasCheckpoint},
};
use wasm_instrument::gas_metering::{host_function, Rules};
use wasmi::core::HostError;

const CANONICAL_LENGTH: usize = 54;
const SHUFFLES_ENCODE: usize = 18;
const SHUFFLES_DECODE: usize = 2;

pub fn initialize() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        env_logger::init();
    });
}

#[derive(PartialEq, Debug)]
enum SimpleVMError {
    Interpreter,
    VMError(WasmiVMError),
    CodeNotFound(CosmwasmCodeId),
    ContractNotFound(BankAccount),
    InvalidAddress,
    InvalidAccountFormat,
    NoCustomQuery,
    NoCustomMessage,
    Unsupported,
    OutOfGas,
    #[cfg(feature = "iterator")]
    IteratorDoesNotExist,
    CannotDeserialize,
    Crypto,
}

impl HostError for SimpleVMError {}

impl From<wasmi::Error> for SimpleVMError {
    fn from(_: wasmi::Error) -> Self {
        Self::Interpreter
    }
}
impl From<WasmiVMError> for SimpleVMError {
    fn from(e: WasmiVMError) -> Self {
        SimpleVMError::VMError(e)
    }
}
impl From<SystemError> for SimpleVMError {
    fn from(e: SystemError) -> Self {
        SimpleVMError::VMError(e.into())
    }
}
impl From<ExecutorError> for SimpleVMError {
    fn from(e: ExecutorError) -> Self {
        SimpleVMError::VMError(e.into())
    }
}
impl From<MemoryReadError> for SimpleVMError {
    fn from(e: MemoryReadError) -> Self {
        SimpleVMError::VMError(e.into())
    }
}
impl From<MemoryWriteError> for SimpleVMError {
    fn from(e: MemoryWriteError) -> Self {
        SimpleVMError::VMError(e.into())
    }
}
impl Display for SimpleVMError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct Gas {
    checkpoints: Vec<u64>,
}

impl Gas {
    fn new(initial_value: u64) -> Self {
        Gas {
            checkpoints: vec![initial_value],
        }
    }
    fn current(&self) -> &u64 {
        self.checkpoints.last().expect("impossible")
    }
    fn current_mut(&mut self) -> &mut u64 {
        self.checkpoints.last_mut().expect("impossible")
    }
    fn push(&mut self, checkpoint: &VmGasCheckpoint) -> Result<(), SimpleVMError> {
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
            VmGasCheckpoint::Limited(_) => Err(SimpleVMError::OutOfGas),
        }
    }
    fn pop(&mut self) {
        let child = self.checkpoints.pop().expect("impossible");
        let parent = self.current_mut();
        *parent += child;
    }
    fn charge(&mut self, value: u64) -> Result<(), SimpleVMError> {
        let current = self.current_mut();
        if *current >= value {
            *current -= value;
            Ok(())
        } else {
            Err(SimpleVMError::OutOfGas)
        }
    }
}

#[cfg(feature = "iterator")]
#[derive(Default, Clone, Debug)]
struct Iter {
    data: Vec<(Vec<u8>, Vec<u8>)>,
    position: usize,
}

#[derive(Default, Clone, Debug)]
struct SimpleWasmiVMStorage {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
    #[cfg(feature = "iterator")]
    iterators: BTreeMap<u32, Iter>,
}

#[cfg(feature = "stargate")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SimpleIBCPacket {
    channel_id: String,
    data: Binary,
    timeout: IbcTimeout,
}

#[cfg(feature = "stargate")]
#[derive(Default, Clone, Debug, PartialEq, Eq)]
struct SimpleIBCState {
    packets_sent: Vec<SimpleIBCPacket>,
}

#[derive(Default, Clone)]
struct SimpleWasmiVMExtension {
    #[cfg(feature = "stargate")]
    ibc: BTreeMap<BankAccount, SimpleIBCState>,
    storage: BTreeMap<BankAccount, SimpleWasmiVMStorage>,
    codes: BTreeMap<CosmwasmCodeId, Vec<u8>>,
    contracts: BTreeMap<BankAccount, CosmwasmContractMeta<BankAccount>>,
    next_account_id: BankAccount,
    transaction_depth: u32,
    gas: Gas,
}

struct SimpleWasmiVM<'a> {
    executing_module: Option<WasmiModule>,
    env: Env,
    info: MessageInfo,
    extension: &'a mut SimpleWasmiVMExtension,
    call_depth: u32,
}

impl<'a> WasmiContext for SimpleWasmiVM<'a> {
    fn executing_module(&self) -> Option<WasmiModule> {
        self.executing_module.clone()
    }

    fn set_wasmi_context(&mut self, instance: wasmi::Instance, memory: wasmi::Memory) {
        self.executing_module = Some(WasmiModule { instance, memory });
    }

    fn call_depth_mut(&mut self) -> &mut u32 {
        &mut self.call_depth
    }
}

impl<'a> SimpleWasmiVM<'a> {
    fn load_subvm(
        &mut self,
        address: <Self as VMBase>::Address,
        funds: Vec<Coin>,
    ) -> Result<OwnedWasmiVM<SimpleWasmiVM>, VmErrorOf<Self>> {
        log::debug!("Loading sub-vm, contract address: {:?}", address);
        let code = (|| {
            let CosmwasmContractMeta { code_id, .. } = self
                .extension
                .contracts
                .get(&address)
                .cloned()
                .ok_or(SimpleVMError::ContractNotFound(address))?;
            self.extension
                .codes
                .get(&code_id)
                .ok_or(SimpleVMError::CodeNotFound(code_id))
                .cloned()
        })()?;
        let sub_vm = SimpleWasmiVM {
            executing_module: None,
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
            extension: self.extension,
            call_depth: 0,
        };
        let sub_vm = new_wasmi_vm::<SimpleWasmiVM>(&code, sub_vm)?;
        Ok(sub_vm)
    }
}

#[derive(Debug, Clone)]
struct CanonicalAddress(pub CanonicalAddr);

impl TryFrom<Vec<u8>> for CanonicalAddress {
    type Error = SimpleVMError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(CanonicalAddress(CanonicalAddr(Binary::from(value))))
    }
}

impl From<CanonicalAddress> for Vec<u8> {
    fn from(addr: CanonicalAddress) -> Self {
        addr.0.into()
    }
}

impl From<CanonicalAddress> for CanonicalAddr {
    fn from(addr: CanonicalAddress) -> Self {
        addr.0
    }
}

impl<'a> VMBase for SimpleWasmiVM<'a> {
    type Input<'x> = WasmiInput<OwnedWasmiVM<Self>>;
    type Output<'x> = WasmiOutput<OwnedWasmiVM<Self>>;
    type QueryCustom = Empty;
    type MessageCustom = Empty;
    type ContractMeta = CosmwasmContractMeta<BankAccount>;
    type Address = BankAccount;
    type CanonicalAddress = CanonicalAddress;
    type StorageKey = Vec<u8>;
    type StorageValue = Vec<u8>;
    type Error = SimpleVMError;

    fn running_contract_meta(&mut self) -> Result<Self::ContractMeta, Self::Error> {
        Ok(self
            .extension
            .contracts
            .get(
                &BankAccount::try_from(self.env.contract.address.clone())
                    .expect("contract address is set by vm, this should never happen"),
            )
            .cloned()
            .expect("contract is inserted by vm, this should never happen"))
    }

    fn set_contract_meta(
        &mut self,
        address: Self::Address,
        contract_meta: Self::ContractMeta,
    ) -> Result<(), Self::Error> {
        let meta = self
            .extension
            .contracts
            .get_mut(&address)
            .ok_or(SimpleVMError::ContractNotFound(address))?;

        *meta = contract_meta;

        Ok(())
    }

    fn contract_meta(&mut self, address: Self::Address) -> Result<Self::ContractMeta, Self::Error> {
        self.extension
            .contracts
            .get_mut(&address)
            .ok_or(SimpleVMError::ContractNotFound(address))
            .cloned()
    }

    fn continue_query(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<QueryResult, Self::Error> {
        let mut sub_vm = self.load_subvm(address, vec![])?;
        cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(&mut sub_vm, message)
    }

    fn continue_execute(
        &mut self,
        address: Self::Address,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        let mut sub_vm = self.load_subvm(address, funds)?;
        cosmwasm_system_run::<ExecuteCall<Self::MessageCustom>, _>(
            &mut sub_vm,
            message,
            event_handler,
        )
    }

    fn continue_instantiate(
        &mut self,
        contract_meta: Self::ContractMeta,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<(Self::Address, Option<Binary>), Self::Error> {
        let BankAccount(address) = self.extension.next_account_id;
        self.extension.next_account_id = BankAccount(address + 1);
        self.extension
            .contracts
            .insert(BankAccount(address), contract_meta);

        let mut sub_vm = self.load_subvm(BankAccount(address), funds)?;
        cosmwasm_system_run::<InstantiateCall<Self::MessageCustom>, _>(
            &mut sub_vm,
            message,
            event_handler,
        )
        .map(|data| (BankAccount(address), data))
    }

    fn continue_instantiate2(
        &mut self,
        contract_meta: Self::ContractMeta,
        funds: Vec<Coin>,
        message: &[u8],
        _salt: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<(Self::Address, Option<Binary>), Self::Error> {
        let BankAccount(address) = self.extension.next_account_id;
        self.extension.next_account_id = BankAccount(address + 1);
        self.extension
            .contracts
            .insert(BankAccount(address), contract_meta);

        let mut sub_vm = self.load_subvm(BankAccount(address), funds)?;
        cosmwasm_system_run::<InstantiateCall<Self::MessageCustom>, _>(
            &mut sub_vm,
            message,
            event_handler,
        )
        .map(|data| (BankAccount(address), data))
    }

    fn continue_migrate(
        &mut self,
        address: Self::Address,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        let mut sub_vm = self.load_subvm(address, vec![])?;
        cosmwasm_system_run::<MigrateCall<Self::MessageCustom>, _>(
            &mut sub_vm,
            message,
            event_handler,
        )
    }

    fn continue_reply(
        &mut self,
        message: Reply,
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        let mut sub_vm = self.load_subvm(
            self.env.contract.address.clone().into_string().try_into()?,
            vec![],
        )?;

        cosmwasm_system_run::<ReplyCall<Self::MessageCustom>, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut sub_vm,
            &serde_json::to_vec(&message).map_err(|_| SimpleVMError::CannotDeserialize)?,
            event_handler,
        )
    }

    fn query_custom(
        &mut self,
        _: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, Self::Error> {
        Err(SimpleVMError::NoCustomQuery)
    }

    fn message_custom(
        &mut self,
        _: Self::MessageCustom,
        _: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        Err(SimpleVMError::NoCustomMessage)
    }

    fn query_raw(
        &mut self,
        address: Self::Address,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error> {
        Ok(self
            .extension
            .storage
            .get(&address)
            .unwrap_or(&SimpleWasmiVMStorage::default())
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
        log::debug!("Transfer from: {:?} -> {:?}\n{:?}", from, to, funds);
        Ok(())
    }

    fn transfer(&mut self, to: &Self::Address, funds: &[Coin]) -> Result<(), Self::Error> {
        log::debug!(
            "Transfer: {:?} -> {:?}\n{:?}",
            self.env.contract.address,
            to,
            funds
        );
        Ok(())
    }

    fn burn(&mut self, funds: &[Coin]) -> Result<(), Self::Error> {
        log::debug!("Burn: {:?}\n{:?}", self.env.contract.address, funds);
        Ok(())
    }

    fn balance(&mut self, _: &Self::Address, _: String) -> Result<Coin, Self::Error> {
        log::debug!("Query balance.");
        Err(SimpleVMError::Unsupported)
    }

    fn supply(&mut self, _: String) -> Result<Coin, Self::Error> {
        log::debug!("Supply.");
        Err(SimpleVMError::Unsupported)
    }

    fn all_balance(&mut self, _: &Self::Address) -> Result<Vec<Coin>, Self::Error> {
        log::debug!("Query all balance.");
        Ok(vec![])
    }

    fn query_contract_info(
        &mut self,
        _: Self::Address,
    ) -> Result<ContractInfoResponse, Self::Error> {
        Err(SimpleVMError::Unsupported)
    }

    fn query_code_info(&mut self, _: CosmwasmCodeId) -> Result<CodeInfoResponse, Self::Error> {
        Err(SimpleVMError::Unsupported)
    }

    fn debug(&mut self, message: Vec<u8>) -> Result<(), Self::Error> {
        log::info!("[contract-debug] {}", String::from_utf8_lossy(&message));
        Ok(())
    }

    #[cfg(feature = "iterator")]
    fn db_scan(
        &mut self,
        _start: Option<Self::StorageKey>,
        _end: Option<Self::StorageKey>,
        _order: Order,
    ) -> Result<u32, Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        let mut empty = SimpleWasmiVMStorage::default();
        let storage = self
            .extension
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

    #[cfg(feature = "iterator")]
    fn db_next(
        &mut self,
        iterator_id: u32,
    ) -> Result<(Self::StorageKey, Self::StorageValue), Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        let storage = self
            .extension
            .storage
            .get_mut(&contract_addr)
            .ok_or(SimpleVMError::IteratorDoesNotExist)?;

        let iterator = storage
            .iterators
            .get_mut(&iterator_id)
            .ok_or(SimpleVMError::IteratorDoesNotExist)?;

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
            .map_err(|_| SimpleVMError::Crypto)
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
            .map_err(|_| SimpleVMError::Crypto)
    }

    fn ed25519_batch_verify(
        &mut self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<bool, Self::Error> {
        cosmwasm_crypto::ed25519_batch_verify(messages, signatures, public_keys)
            .map_err(|_| SimpleVMError::Crypto)
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
        let account = BankAccount::try_from(input.to_string())?;
        Ok(if account == normalized {
            Ok(())
        } else {
            Err(SimpleVMError::InvalidAddress)
        })
    }

    fn addr_canonicalize(
        &mut self,
        input: &str,
    ) -> Result<Result<Self::CanonicalAddress, Self::Error>, Self::Error> {
        // mimicks formats like hex or bech32 where different casings are valid for one address
        let normalized = input.to_lowercase();

        // Dummy input validation. This is more sophisticated for formats like bech32, where format and checksum are validated.
        if normalized.len() < 3 {
            return Ok(Err(SimpleVMError::InvalidAddress));
        }

        if normalized.len() > CANONICAL_LENGTH {
            return Ok(Err(SimpleVMError::InvalidAddress));
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
            return Ok(Err(SimpleVMError::InvalidAddress));
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
        let Ok(human) = String::from_utf8(trimmed) else { return Ok(Err(SimpleVMError::InvalidAddress)) };
        Ok(
            BankAccount::try_from(Addr::unchecked(human))
                .map_err(|_| SimpleVMError::InvalidAddress),
        )
    }

    fn db_read(
        &mut self,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        let empty = SimpleWasmiVMStorage::default();
        Ok(self
            .extension
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
        self.extension
            .storage
            .entry(contract_addr)
            .or_insert_with(SimpleWasmiVMStorage::default)
            .data
            .insert(key, value);
        Ok(())
    }

    fn db_remove(&mut self, key: Self::StorageKey) -> Result<(), Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        self.extension
            .storage
            .get_mut(&contract_addr)
            .map(|contract_storage| contract_storage.data.remove(&key));
        Ok(())
    }

    fn abort(&mut self, message: String) -> Result<(), Self::Error> {
        log::debug!("Contract aborted: {}", message);
        Err(SimpleVMError::from(WasmiVMError::from(
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
        self.extension.gas.charge(gas_to_charge)?;
        Ok(())
    }

    fn gas_checkpoint_push(&mut self, checkpoint: VmGasCheckpoint) -> Result<(), Self::Error> {
        log::debug!("> Gas before: {:?}", self.extension.gas);
        self.extension.gas.push(&checkpoint)?;
        log::debug!("> Gas after: {:?}", self.extension.gas);
        Ok(())
    }

    fn gas_checkpoint_pop(&mut self) -> Result<(), Self::Error> {
        log::debug!("> Gas before: {:?}", self.extension.gas);
        self.extension.gas.pop();
        log::debug!("> Gas after: {:?}", self.extension.gas);
        Ok(())
    }

    fn gas_ensure_available(&mut self) -> Result<(), Self::Error> {
        let checkpoint = self
            .extension
            .gas
            .checkpoints
            .last()
            .expect("invalis gas checkpoint state");
        if *checkpoint > 0 {
            Ok(())
        } else {
            Err(SimpleVMError::OutOfGas)
        }
    }

    #[cfg(feature = "stargate")]
    fn ibc_transfer(
        &mut self,
        _channel_id: String,
        _to_address: String,
        _amount: Coin,
        _timeout: IbcTimeout,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    #[cfg(feature = "stargate")]
    fn ibc_send_packet(
        &mut self,
        channel_id: String,
        data: Binary,
        timeout: IbcTimeout,
    ) -> Result<(), Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        let entry = self.extension.ibc.entry(contract_addr).or_default();
        entry.packets_sent.push(SimpleIBCPacket {
            channel_id,
            data,
            timeout,
        });
        Ok(())
    }

    #[cfg(feature = "stargate")]
    fn ibc_close_channel(&mut self, _channel_id: String) -> Result<(), Self::Error> {
        todo!()
    }
}

#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct BankAccount(u128);

impl TryFrom<Addr> for BankAccount {
    type Error = SimpleVMError;
    fn try_from(value: Addr) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for BankAccount {
    type Error = SimpleVMError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(BankAccount(
            u128::from_str(&value).map_err(|_| SimpleVMError::InvalidAccountFormat)?,
        ))
    }
}

impl From<BankAccount> for Addr {
    fn from(BankAccount(account): BankAccount) -> Self {
        Addr::unchecked(format!("{account}"))
    }
}

impl<'a> Has<Env> for SimpleWasmiVM<'a> {
    fn get(&self) -> Env {
        self.env.clone()
    }
}
impl<'a> Has<MessageInfo> for SimpleWasmiVM<'a> {
    fn get(&self) -> MessageInfo {
        self.info.clone()
    }
}

impl<'a> Transactional for SimpleWasmiVM<'a> {
    type Error = SimpleVMError;
    fn transaction_begin(&mut self) -> Result<(), Self::Error> {
        self.extension.transaction_depth += 1;
        log::debug!("> Transaction begin: {}", self.extension.transaction_depth);
        Ok(())
    }
    fn transaction_commit(&mut self) -> Result<(), Self::Error> {
        self.extension.transaction_depth -= 1;
        log::debug!("< Transaction end: {}", self.extension.transaction_depth);
        Ok(())
    }
    fn transaction_rollback(&mut self) -> Result<(), Self::Error> {
        self.extension.transaction_depth -= 1;
        log::debug!("< Transaction abort: {}", self.extension.transaction_depth);
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

    fn call_per_local_cost(&self) -> u32 {
        0
    }
}

fn instrument_contract(code: &[u8]) -> Vec<u8> {
    let module =
        wasm_instrument::parity_wasm::elements::Module::from_bytes(code).expect("impossible");
    let instrumented_module = wasm_instrument::gas_metering::inject(
        module,
        host_function::Injector::new(Version1x::ENV_MODULE, Version1x::ENV_GAS),
        &ConstantCostRules,
    )
    .expect("impossible");
    instrumented_module.into_bytes().expect("impossible")
}

fn create_vm(
    extension: &mut SimpleWasmiVMExtension,
    env: Env,
    info: MessageInfo,
) -> Result<OwnedWasmiVM<SimpleWasmiVM>, SimpleVMError> {
    initialize();
    let code = extension
        .codes
        .get(
            &extension
                .contracts
                .get(&env.clone().contract.address.try_into().unwrap())
                .expect("contract should have been uploaded")
                .code_id,
        )
        .expect("contract should have been uploaded")
        .clone();
    let vm = SimpleWasmiVM {
        executing_module: None,
        env,
        info,
        extension,
        call_depth: 0,
    };
    let vm = new_wasmi_vm::<SimpleWasmiVM>(&code, vm)?;
    Ok(vm)
}

fn create_simple_vm(
    sender: BankAccount,
    contract: BankAccount,
    funds: Vec<Coin>,
    extension: &mut SimpleWasmiVMExtension,
) -> Result<OwnedWasmiVM<SimpleWasmiVM>, SimpleVMError> {
    create_vm(
        extension,
        Env {
            block: BlockInfo {
                height: 0xDEAD_C0DE,
                time: Timestamp::from_seconds(10000),
                chain_id: "abstract-test".into(),
            },
            transaction: None,
            contract: ContractInfo {
                address: contract.into(),
            },
        },
        MessageInfo {
            sender: sender.into(),
            funds,
        },
    )
}

#[test]
fn test_bare() {
    let code = instrument_contract(include_bytes!("../../fixtures/cw20_base.wasm"));
    let sender = BankAccount(100);
    let address = BankAccount(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: BTreeMap::default(),
        codes: BTreeMap::from([(0x1337, code)]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: String::new(),
            },
        )]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    assert_matches!(
        cosmwasm_call::<InstantiateCall<Empty>, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{
              "name": "Picasso",
              "symbol": "PICA",
              "decimals": 12,
              "initial_balances": [],
              "mint": null,
              "marketing": null
            }"#
            .as_bytes(),
        )
        .unwrap(),
        InstantiateResult(CosmwasmExecutionResult::Ok(_))
    );
    assert_eq!(
        cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{ "token_info": {} }"#.as_bytes(),
        )
        .unwrap(),
        QueryResult(CosmwasmQueryResult::Ok(Binary(
            r#"{"name":"Picasso","symbol":"PICA","decimals":12,"total_supply":"0"}"#
                .as_bytes()
                .to_vec()
        )))
    );
}

/// Tests behaviour of the runtime when malicious contract causes infinite
/// recursion.
///
/// It’s possible for a contract to cause an infinite recursion within the
/// *host* stack.  This is because host functions call contract’s `allocate` and
/// `deallocate` functions to manage memory within contract’s address space.
/// Unconditionally calling host function inside of an `allocate` can easily
/// lead to host recusing indefinitely and eventually crashing.
///
/// This test checks whether recursion depth limit is correctly implemented.
#[test]
fn test_recursion() {
    let code = instrument_contract(include_bytes!("../../fixtures/recursion_test.wasm"));
    let sender = BankAccount(100);
    let address = BankAccount(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: BTreeMap::default(),
        codes: BTreeMap::from([(0x1337, code)]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: String::new(),
            },
        )]),
        next_account_id: BankAccount(10_001),
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    assert_eq!(
        cosmwasm_call::<InstantiateCall<Empty>, OwnedWasmiVM<SimpleWasmiVM>>(&mut vm, b"{}"),
        Err(SimpleVMError::Interpreter)
    );
}

mod test_code_gen {
    use cosmwasm_std::{ContractResult, Response};

    use super::*;
    #[test]
    fn basic() {
        let module: code_gen::WasmModule = code_gen::ModuleDefinition::new(vec![], 10, None)
            .unwrap()
            .into();
        let sender = BankAccount(100);
        let address = BankAccount(10_000);
        let funds = vec![];
        let mut extension = SimpleWasmiVMExtension {
            storage: BTreeMap::default(),
            codes: BTreeMap::from([(0x1337, module.code)]),
            contracts: BTreeMap::from([(
                address,
                CosmwasmContractMeta {
                    code_id: 0x1337,
                    admin: None,
                    label: String::new(),
                },
            )]),
            next_account_id: BankAccount(10_001),
            transaction_depth: 0,
            gas: Gas::new(100_000_000),
            ..Default::default()
        };
        let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
        let result = cosmwasm_call::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{}"#.as_bytes(),
        )
        .unwrap();
        assert_matches!(result, InstantiateResult(CosmwasmExecutionResult::Ok(_)));
        let result =
            cosmwasm_call::<ExecuteCall, OwnedWasmiVM<SimpleWasmiVM>>(&mut vm, r#"{}"#.as_bytes())
                .unwrap();
        assert_matches!(result, ExecuteResult(CosmwasmExecutionResult::Ok(_)));
    }

    #[test]
    fn instantiate_response() {
        let response =
            ContractResult::Ok(Response::<Empty>::new().add_attribute("Hello", "world!"));
        let response_2 =
            ContractResult::Ok(Response::<Empty>::new().add_attribute("Hello", "mars!"));
        let module: code_gen::WasmModule =
            code_gen::ModuleDefinition::with_instantiate_response(response.clone())
                .unwrap()
                .into();

        let sender = BankAccount(100);
        let address = BankAccount(10_000);
        let funds = vec![];
        let mut extension = SimpleWasmiVMExtension {
            storage: BTreeMap::default(),
            codes: BTreeMap::from([(0x1337, module.code)]),
            contracts: BTreeMap::from([(
                address,
                CosmwasmContractMeta {
                    code_id: 0x1337,
                    admin: None,
                    label: String::new(),
                },
            )]),
            next_account_id: BankAccount(10_001),
            transaction_depth: 0,
            gas: Gas::new(100_000_000),
            ..Default::default()
        };
        let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
        let result = cosmwasm_call::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{}"#.as_bytes(),
        )
        .unwrap();
        assert_eq!(result, InstantiateResult(response));
        assert_ne!(result, InstantiateResult(response_2));
    }
}

pub fn digit_sum(input: &[u8]) -> usize {
    input.iter().map(|v| *v as usize).sum()
}

pub fn riffle_shuffle<T: Clone>(input: &[T]) -> Vec<T> {
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

#[test]
fn test_orchestration_base() {
    let code = instrument_contract(include_bytes!("../../fixtures/cw20_base.wasm"));
    let sender = BankAccount(100);
    let address = BankAccount(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: BTreeMap::default(),
        codes: BTreeMap::from([(0x1337, code)]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: String::new(),
            },
        )]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    let _ = cosmwasm_system_entrypoint::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(
        &mut vm,
        format!(
            r#"{{
                  "name": "Picasso",
                  "symbol": "PICA",
                  "decimals": 12,
                  "initial_balances": [],
                  "mint": {{
                    "minter": "{}",
                    "cap": null
                  }},
                  "marketing": null
                }}"#,
            sender.0
        )
        .as_bytes(),
    )
    .unwrap();

    let (_, events) = cosmwasm_system_entrypoint::<ExecuteCall, OwnedWasmiVM<SimpleWasmiVM>>(
        &mut vm,
        r#"{
              "mint": {
                "recipient": "10001",
                "amount": "5555"
              }
            }"#
        .as_bytes(),
    )
    .unwrap();
    let attributes = vec![
        Attribute {
            key: "action".into(),
            value: "mint".into(),
        },
        Attribute {
            key: "to".into(),
            value: "10001".into(),
        },
        Attribute {
            key: "amount".into(),
            value: "5555".into(),
        },
    ];

    for attr in attributes {
        assert!(events.iter().any(|e| e.attributes.contains(&attr)));
    }
}

#[test]
fn test_orchestration_advanced() {
    let code = instrument_contract(include_bytes!("../../fixtures/hackatom.wasm"));
    let sender = BankAccount(100);
    let address = BankAccount(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: BTreeMap::default(),
        codes: BTreeMap::from([(0x1337, code)]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: String::new(),
            },
        )]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    assert_eq!(
        cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{ "recurse": { "depth": 10, "work": 10 }}"#.as_bytes()
        )
        .unwrap(),
        QueryResult(CosmwasmQueryResult::Ok(Binary(
            r#"{"hashed":"K4xL+Gub1930CJU6hdpwf0t3KNk27f5efqy9+YA6iio="}"#
                .as_bytes()
                .to_vec()
        )))
    );
}

#[test]
fn test_hook() {
    let code = instrument_contract(include_bytes!("../../fixtures/cw20_base.wasm"));
    let sender = BankAccount(100);
    let address = BankAccount(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: BTreeMap::default(),
        codes: BTreeMap::from([(0x1337, code)]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: String::new(),
            },
        )]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    let _ = cosmwasm_system_entrypoint_hook::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(
        &mut vm,
        format!(
            r#"{{
                  "name": "Picasso",
                  "symbol": "PICA",
                  "decimals": 12,
                  "initial_balances": [],
                  "mint": {{
                    "minter": "{}",
                    "cap": null
                  }},
                  "marketing": null
                }}"#,
            sender.0
        )
        .as_bytes(),
        |vm, msg| {
            cosmwasm_call::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(vm, msg).map(Into::into)
        },
    )
    .unwrap();
    let r = cosmwasm_system_entrypoint_hook::<ExecuteCall, OwnedWasmiVM<SimpleWasmiVM>>(
        &mut vm,
        r#"{
              "mint": {
                "recipient": "10001",
                "amount": "5555"
              }
            }"#
        .as_bytes(),
        |_, _| Ok(ContractResult::Err("Bro".into())),
    );
    assert_eq!(
        r,
        Err(SimpleVMError::VMError(WasmiVMError::SystemError(
            SystemError::ContractExecutionFailure("Bro".into())
        )))
    );
}

#[test]
fn test_reply() {
    let code = instrument_contract(include_bytes!("../../fixtures/reflect.wasm"));
    let code_hackatom = instrument_contract(include_bytes!("../../fixtures/hackatom.wasm"));
    let sender = BankAccount(100);
    let address = BankAccount(10_000);
    let hackatom_address = BankAccount(10_001);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: BTreeMap::default(),
        codes: BTreeMap::from([(0x1337, code), (0x1338, code_hackatom)]),
        contracts: BTreeMap::from([
            (
                address,
                CosmwasmContractMeta {
                    code_id: 0x1337,
                    admin: None,
                    label: String::new(),
                },
            ),
            (
                hackatom_address,
                CosmwasmContractMeta {
                    code_id: 0x1338,
                    admin: None,
                    label: String::new(),
                },
            ),
        ]),
        next_account_id: BankAccount(10_002),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    {
        let mut vm =
            create_simple_vm(address, hackatom_address, funds.clone(), &mut extension).unwrap();
        let (_, events) = cosmwasm_system_entrypoint::<InstantiateCall, _>(
            &mut vm,
            r#"{"verifier": "10000", "beneficiary": "10000"}"#.as_bytes(),
        )
        .unwrap();

        assert!(events.iter().any(|e| e.attributes.contains(&Attribute {
            key: "Let the".into(),
            value: "hacking begin".into()
        })));
    }
    log::debug!("{:?}", extension.storage);
    {
        let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
        let _ = cosmwasm_system_entrypoint::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{}"#.as_bytes(),
        )
        .unwrap();

        let (_, events) = cosmwasm_system_entrypoint::<ExecuteCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{
                  "reflect_sub_msg": {
                    "msgs": [{
                      "id": 10,
                      "msg": {
                        "wasm": {
                          "execute": {
                            "contract_addr": "10001",
                            "msg": "eyAicmVsZWFzZSI6IHt9IH0=",
                            "funds": []
                          }
                        }
                      },
                      "gas_limit": null,
                      "reply_on": "always"
                    }]
                  }
                }"#
            .as_bytes(),
        )
        .unwrap();

        let attributes = vec![
            Attribute {
                key: "action".into(),
                value: "release".into(),
            },
            Attribute {
                key: "destination".into(),
                value: "10000".into(),
            },
            Attribute {
                key: "action".into(),
                value: "reflect_subcall".into(),
            },
        ];

        for attr in attributes {
            assert!(events.iter().any(|e| e.attributes.contains(&attr)));
        }
    }
}

#[cfg(feature = "stargate")]
mod cw20_ics20 {
    use super::{
        create_vm, instrument_contract, BankAccount, Gas, OwnedWasmiVM, SimpleIBCPacket,
        SimpleIBCState, SimpleWasmiVM, SimpleWasmiVMExtension,
    };

    use super::{assert_matches, format, vec};
    use alloc::{collections::BTreeMap, string::String, vec::Vec};
    use cosmwasm_std::{
        Addr, Binary, BlockInfo, Coin, ContractInfo, ContractResult, Env, IbcChannel,
        IbcChannelConnectMsg, IbcChannelOpenMsg, IbcEndpoint, IbcOrder, IbcPacket,
        IbcPacketReceiveMsg, MessageInfo, Timestamp, Uint128,
    };
    use cosmwasm_vm::{
        executor::{
            cosmwasm_call_serialize,
            ibc::{
                IbcChannelConnectCall, IbcChannelOpenCall, IbcChannelOpenResult,
                IbcPacketReceiveCall,
            },
            ExecuteCall, InstantiateCall,
        },
        system::{
            cosmwasm_system_entrypoint, cosmwasm_system_entrypoint_serialize, CosmwasmContractMeta,
        },
    };
    use cw20_ics20::ibc::{Ics20Ack, Ics20Packet};

    const DEFAULT_TIMEOUT: u64 = 3600;
    const CONTRACT_PORT: &str = "ibc:wasm1234567890abcdef";
    const REMOTE_PORT: &str = "transfer";
    const CONNECTION_ID: &str = "connection-2";
    const ICS20_VERSION: &str = "ics20-1";

    fn funded(funds: Vec<Coin>, info: MessageInfo) -> MessageInfo {
        MessageInfo {
            sender: info.sender,
            funds,
        }
    }

    fn create_channel(channel_id: &str) -> IbcChannel {
        IbcChannel::new(
            IbcEndpoint {
                port_id: CONTRACT_PORT.into(),
                channel_id: channel_id.into(),
            },
            IbcEndpoint {
                port_id: REMOTE_PORT.into(),
                channel_id: channel_id.into(),
            },
            IbcOrder::Unordered,
            ICS20_VERSION,
            CONNECTION_ID,
        )
    }

    fn reverse_channel(channel: IbcChannel) -> IbcChannel {
        IbcChannel::new(
            channel.counterparty_endpoint,
            channel.endpoint,
            channel.order,
            channel.version,
            channel.connection_id,
        )
    }

    fn reverse_packet(
        channel: IbcChannel,
        Ics20Packet {
            amount,
            denom,
            receiver,
            sender,
        }: Ics20Packet,
    ) -> Ics20Packet {
        let reversed_channel = reverse_channel(channel);
        Ics20Packet {
            amount,
            denom: format!(
                "{}/{}/{}",
                reversed_channel.endpoint.port_id, reversed_channel.endpoint.channel_id, denom
            ),
            receiver: sender,
            sender: receiver,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_ics20_ibc_orchestration() {
        // State setup
        let code = instrument_contract(include_bytes!("../../fixtures/cw20_ics20.wasm"));
        let sender = BankAccount(100);
        let contract = BankAccount(10_000);
        let funds = vec![];
        let env = Env {
            block: BlockInfo {
                height: 0xDEAD_C0DE,
                time: Timestamp::from_seconds(10000),
                chain_id: "abstract-test".into(),
            },
            transaction: None,
            contract: ContractInfo {
                address: contract.into(),
            },
        };
        let info = MessageInfo {
            sender: sender.into(),
            funds,
        };
        let mut extension = SimpleWasmiVMExtension {
            storage: BTreeMap::default(),
            codes: BTreeMap::from([(0x1337, code)]),
            contracts: BTreeMap::from([(
                contract,
                CosmwasmContractMeta {
                    code_id: 0x1337,
                    admin: None,
                    label: String::new(),
                },
            )]),
            next_account_id: BankAccount(10_001),
            transaction_depth: 0,
            gas: Gas::new(100_000_000),
            ..Default::default()
        };

        // IBC channel opening
        let channel_name = "PicassoXTerra";
        let channel = create_channel(channel_name);

        {
            let mut vm = create_vm(&mut extension, env.clone(), info.clone()).unwrap();

            // Contract instantiation
            assert_matches!(
                cosmwasm_system_entrypoint::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(
                    &mut vm,
                    format!(
                        r#"{{
                      "default_gas_limit": null,
                      "default_timeout": {},
                      "gov_contract": "{}",
                      "allowlist": []
                    }}"#,
                        DEFAULT_TIMEOUT, sender.0
                    )
                    .as_bytes(),
                ),
                Ok(_)
            );

            assert_matches!(
                cosmwasm_call_serialize::<IbcChannelOpenCall, OwnedWasmiVM<SimpleWasmiVM>, _>(
                    &mut vm,
                    &IbcChannelOpenMsg::OpenInit {
                        channel: channel.clone()
                    }
                )
                .unwrap(),
                IbcChannelOpenResult(ContractResult::Ok(None))
            );
            assert_matches!(
                cosmwasm_system_entrypoint_serialize::<
                    IbcChannelConnectCall,
                    OwnedWasmiVM<SimpleWasmiVM>,
                    _,
                >(
                    &mut vm,
                    &IbcChannelConnectMsg::OpenAck {
                        channel: channel.clone(),
                        counterparty_version: ICS20_VERSION.into(),
                    },
                ),
                Ok(_)
            );
        }

        {
            // Actual cross-chain execution
            let mut vm = create_vm(
                &mut extension,
                env.clone(),
                funded(
                    vec![Coin {
                        denom: "PICA".into(),
                        amount: Uint128::new(1000),
                    }],
                    info.clone(),
                ),
            )
            .unwrap();
            assert_matches!(
                cosmwasm_system_entrypoint::<ExecuteCall, OwnedWasmiVM<SimpleWasmiVM>>(
                    &mut vm,
                    format!(
                        r#"{{
                      "transfer": {{
                        "channel": "{channel_name}",
                        "remote_address": "0",
                        "timeout": null
                      }}
                    }}"#
                    )
                    .as_bytes(),
                ),
                Ok(_)
            );
        }

        // cw20-ics20 is symmetric, we should be able to forward sent packets
        // back to the contract by reverting the channel/packets
        let (_next_seq, packets_to_dispatch) = extension.ibc.iter().fold(
            (
                0u64,
                Vec::with_capacity(extension.ibc.values().map(|x| x.packets_sent.len()).sum()),
            ),
            |(next_seq, mut packets_to_dispatch), (_, SimpleIBCState { packets_sent })| {
                packets_sent.iter().enumerate().for_each(
                    |(i, SimpleIBCPacket { data, timeout, .. })| {
                        let packet = serde_json::from_slice::<Ics20Packet>(data.as_ref()).unwrap();
                        packets_to_dispatch.push(IbcPacket::new(
                            Binary::from(
                                serde_json::to_vec(&reverse_packet(channel.clone(), packet))
                                    .unwrap(),
                            ),
                            channel.counterparty_endpoint.clone(),
                            channel.endpoint.clone(),
                            next_seq + i as u64,
                            timeout.clone(),
                        ));
                    },
                );
                (next_seq + packets_sent.len() as u64, packets_to_dispatch)
            },
        );

        let mut vm = create_vm(&mut extension, env, info).unwrap();
        #[cfg(feature = "ibc3")]
        let make_receive_msg = |packet| IbcPacketReceiveMsg::new(packet, Addr::unchecked("1337"));
        #[cfg(not(feature = "ibc3"))]
        let make_receive_msg = |packet| IbcPacketReceiveMsg::new(packet);
        for packet in packets_to_dispatch {
            let (acknowledgment, _events) = cosmwasm_system_entrypoint_serialize::<
                IbcPacketReceiveCall,
                OwnedWasmiVM<SimpleWasmiVM>,
                _,
            >(&mut vm, &make_receive_msg(packet))
            .unwrap();
            let acknowledgment =
                serde_json::from_slice::<Ics20Ack>(acknowledgment.unwrap().as_ref()).unwrap();
            /*
            See `ack_success` in cw20-ics20 ibs.rs

            // create a serialized success message
            fn ack_success() -> Binary {
              let res = Ics20Ack::Result(b"1".into());
              to_binary(&res).unwrap()
            }
            */
            assert_eq!(acknowledgment, Ics20Ack::Result(b"1".into()));
        }
    }
}
