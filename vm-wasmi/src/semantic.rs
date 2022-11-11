extern crate std;

use super::*;
use alloc::{boxed::Box, string::ToString};
use core::{assert_matches::assert_matches, num::NonZeroU32, str::FromStr};
#[cfg(feature = "stargate")]
use cosmwasm_minimal_std::ibc::IbcTimeout;
#[cfg(feature = "iterator")]
use cosmwasm_minimal_std::Order;
use cosmwasm_minimal_std::{
    ibc::{IbcChannel, IbcChannelOpenMsg, IbcEndpoint, IbcOrder},
    Addr, Attribute, Binary, BlockInfo, Coin, ContractInfo, ContractResult, Empty, Env, Event,
    MessageInfo, Timestamp,
};
use cosmwasm_vm::{
    executor::{
        cosmwasm_call, cosmwasm_call_serialize,
        ibc::{IbcChannelConnectInput, IbcChannelOpenInput, IbcChannelOpenResult},
        CosmwasmExecutionResult, ExecuteInput, ExecuteResult, InstantiateInput, InstantiateResult,
        MigrateInput, QueryInput,
    },
    system::{
        cosmwasm_system_entrypoint, cosmwasm_system_run, CosmwasmCodeId, CosmwasmContractMeta,
    },
};
use std::error::Error;
use wasm_instrument::gas_metering::Rules;

const CANONICAL_LENGTH: usize = 54;
const SHUFFLES_ENCODE: usize = 18;
const SHUFFLES_DECODE: usize = 2;

fn initialize() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        env_logger::init();
    });
}

#[derive(Debug)]
enum SimpleVMError {
    Interpreter(wasmi::Error),
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
    Custom(Box<dyn Error>),
}
impl From<wasmi::Error> for SimpleVMError {
    fn from(e: wasmi::Error) -> Self {
        Self::Interpreter(e)
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
        write!(f, "{:?}", self)
    }
}
impl CanResume for SimpleVMError {
    fn can_resume(&self) -> bool {
        false
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
    fn push(&mut self, checkpoint: VmGasCheckpoint) -> Result<(), SimpleVMError> {
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
            _ => Err(SimpleVMError::OutOfGas),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SimpleIBCPacket {
    channel_id: String,
    data: Binary,
    timeout: IbcTimeout,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
struct SimpleIBCState {
    packets_sent: Vec<SimpleIBCPacket>,
}

#[derive(Default, Clone)]
struct SimpleWasmiVMExtension {
    ibc: BTreeMap<BankAccount, SimpleIBCState>,
    storage: BTreeMap<BankAccount, SimpleWasmiVMStorage>,
    codes: BTreeMap<CosmwasmCodeId, Vec<u8>>,
    contracts: BTreeMap<BankAccount, CosmwasmContractMeta<BankAccount>>,
    next_account_id: BankAccount,
    transaction_depth: u32,
    gas: Gas,
}

struct SimpleWasmiVM<'a> {
    host_functions: BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<Self>>,
    executing_module: WasmiModule,
    env: Env,
    info: MessageInfo,
    extension: &'a mut SimpleWasmiVMExtension,
}

impl<'a> WasmiModuleExecutor for SimpleWasmiVM<'a> {
    fn executing_module(&self) -> WasmiModule {
        self.executing_module.clone()
    }
    fn host_function(&self, index: WasmiHostFunctionIndex) -> Option<&WasmiHostFunction<Self>> {
        self.host_functions.get(&index)
    }
}

impl<'a> Pointable for SimpleWasmiVM<'a> {
    type Pointer = u32;
}

impl<'a> ReadableMemory for SimpleWasmiVM<'a> {
    type Error = VmErrorOf<Self>;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.executing_module
            .memory
            .get_into(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryReadError.into())
    }
}

impl<'a> WritableMemory for SimpleWasmiVM<'a> {
    type Error = VmErrorOf<Self>;
    fn write(&self, offset: Self::Pointer, buffer: &[u8]) -> Result<(), Self::Error> {
        self.executing_module
            .memory
            .set(offset, buffer)
            .map_err(|_| WasmiVMError::LowLevelMemoryWriteError.into())
    }
}

impl<'a> ReadWriteMemory for SimpleWasmiVM<'a> {}

impl<'a> SimpleWasmiVM<'a> {
    fn load_subvm<R>(
        &mut self,
        address: <Self as VMBase>::Address,
        funds: Vec<Coin>,
        f: impl FnOnce(&mut WasmiVM<SimpleWasmiVM>) -> R,
    ) -> Result<R, VmErrorOf<Self>> {
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
        let host_functions_definitions =
            WasmiImportResolver(host_functions::definitions::<SimpleWasmiVM>());
        let module = new_wasmi_vm(&host_functions_definitions, &code)?;
        let mut sub_vm: WasmiVM<SimpleWasmiVM> = WasmiVM(SimpleWasmiVM {
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
            extension: self.extension,
        });
        Ok(f(&mut sub_vm))
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
    type Input<'x> = WasmiInput<'x, WasmiVM<Self>>;
    type Output<'x> = WasmiOutput<'x, WasmiVM<Self>>;
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

    fn query_continuation(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<QueryResult, Self::Error> {
        self.load_subvm(address, vec![], |sub_vm| {
            cosmwasm_call::<QueryInput, WasmiVM<SimpleWasmiVM>>(sub_vm, message)
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
        let BankAccount(address) = self.extension.next_account_id;
        self.extension.next_account_id = BankAccount(address + 1);
        self.extension
            .contracts
            .insert(BankAccount(address), contract_meta);

        self.load_subvm(BankAccount(address), funds, |sub_vm| {
            cosmwasm_system_run::<InstantiateInput<Self::MessageCustom>, _>(
                sub_vm,
                message,
                event_handler,
            )
        })?
        .map(|data| (BankAccount(address), data))
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

    fn all_balance(&mut self, _: &Self::Address) -> Result<Vec<Coin>, Self::Error> {
        log::debug!("Query all balance.");
        Ok(vec![])
    }

    fn query_info(
        &mut self,
        _: Self::Address,
    ) -> Result<cosmwasm_minimal_std::ContractInfoResponse, Self::Error> {
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
            .map_err(|e| SimpleVMError::Custom(Box::new(e)))
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
            .map_err(|e| SimpleVMError::Custom(Box::new(e)))
    }

    fn ed25519_batch_verify(
        &mut self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<bool, Self::Error> {
        cosmwasm_crypto::ed25519_batch_verify(messages, signatures, public_keys)
            .map_err(|e| SimpleVMError::Custom(Box::new(e)))
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
        if account != normalized {
            Ok(Err(SimpleVMError::InvalidAddress))
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
        let human = match String::from_utf8(trimmed) {
            Ok(trimmed) => trimmed,
            Err(_) => return Ok(Err(SimpleVMError::InvalidAddress)),
        };
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
            VmGas::Instrumentation { metered } => metered as u64,
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
        self.extension.gas.push(checkpoint)?;
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
        channel_id: String,
        to_address: String,
        amount: Coin,
        timeout: IbcTimeout,
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
    fn ibc_close_channel(&mut self, channel_id: String) -> Result<(), Self::Error> {
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
        Addr::unchecked(format!("{}", account))
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
}

fn instrument_contract(code: &[u8]) -> Vec<u8> {
    let module =
        wasm_instrument::parity_wasm::elements::Module::from_bytes(code).expect("impossible");
    let instrumented_module =
        wasm_instrument::gas_metering::inject(module, &ConstantCostRules, "env")
            .expect("impossible");
    instrumented_module.into_bytes().expect("impossible")
}

fn create_vm<'a>(
    extension: &'a mut SimpleWasmiVMExtension,
    env: Env,
    info: MessageInfo,
) -> WasmiVM<SimpleWasmiVM<'a>> {
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
        .expect("contract should have been uploaded");
    let host_functions_definitions = WasmiImportResolver(host_functions::definitions());
    let module = new_wasmi_vm(&host_functions_definitions, code).unwrap();
    WasmiVM(SimpleWasmiVM {
        host_functions: host_functions_definitions
            .0
            .clone()
            .into_iter()
            .flat_map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
            .collect(),
        executing_module: module,
        env,
        info,
        extension,
    })
}

fn create_simple_vm<'a>(
    sender: BankAccount,
    contract: BankAccount,
    funds: Vec<Coin>,
    extension: &'a mut SimpleWasmiVMExtension,
) -> WasmiVM<SimpleWasmiVM<'a>> {
    create_vm(
        extension,
        Env {
            block: BlockInfo {
                height: 0xDEADC0DE,
                time: Timestamp(10000),
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
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone())]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: "".into(),
            },
        )]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    let mut vm = create_simple_vm(sender, address, funds, &mut extension);
    assert_matches!(
        cosmwasm_call::<InstantiateInput<Empty>, WasmiVM<SimpleWasmiVM>>(
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
        cosmwasm_call::<QueryInput, WasmiVM<SimpleWasmiVM>>(
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

#[test]
fn test_code_gen() {
    let code: code_gen::WasmModule = code_gen::ModuleDefinition::new(vec![], 10).unwrap().into();
    let sender = BankAccount(100);
    let address = BankAccount(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.code.clone())]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: "".into(),
            },
        )]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    let mut vm = create_simple_vm(sender, address, funds, &mut extension);
    let result =
        cosmwasm_call::<InstantiateInput, WasmiVM<SimpleWasmiVM>>(&mut vm, r#"{}"#.as_bytes())
            .unwrap();
    assert_matches!(result, InstantiateResult(CosmwasmExecutionResult::Ok(_)));
    let result =
        cosmwasm_call::<ExecuteInput, WasmiVM<SimpleWasmiVM>>(&mut vm, r#"{}"#.as_bytes()).unwrap();
    assert_matches!(result, ExecuteResult(CosmwasmExecutionResult::Ok(_)));
}

pub fn digit_sum(input: &[u8]) -> usize {
    input.iter().fold(0, |sum, val| sum + (*val as usize))
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
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone())]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: "".into(),
            },
        )]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    let mut vm = create_simple_vm(sender, address, funds, &mut extension);
    let _ = cosmwasm_system_entrypoint::<InstantiateInput, WasmiVM<SimpleWasmiVM>>(
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

    let (_, events) = cosmwasm_system_entrypoint::<ExecuteInput, WasmiVM<SimpleWasmiVM>>(
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
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone())]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: "".into(),
            },
        )]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    let mut vm = create_simple_vm(sender, address, funds, &mut extension);
    assert_eq!(
        cosmwasm_call::<QueryInput, WasmiVM<SimpleWasmiVM>>(
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
fn test_reply() {
    let code = instrument_contract(include_bytes!("../../fixtures/reflect.wasm"));
    let code_hackatom = instrument_contract(include_bytes!("../../fixtures/hackatom.wasm"));
    let sender = BankAccount(100);
    let address = BankAccount(10_000);
    let hackatom_address = BankAccount(10_001);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone()), (0x1338, code_hackatom)]),
        contracts: BTreeMap::from([
            (
                address,
                CosmwasmContractMeta {
                    code_id: 0x1337,
                    admin: None,
                    label: "".into(),
                },
            ),
            (
                hackatom_address,
                CosmwasmContractMeta {
                    code_id: 0x1338,
                    admin: None,
                    label: "".into(),
                },
            ),
        ]),
        next_account_id: BankAccount(10_002),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
    {
        let mut vm = create_simple_vm(address, hackatom_address, funds.clone(), &mut extension);
        let (_, events) = cosmwasm_system_entrypoint::<InstantiateInput, _>(
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
        let mut vm = create_simple_vm(sender, address, funds, &mut extension);
        let _ = cosmwasm_system_entrypoint::<InstantiateInput, WasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{}"#.as_bytes(),
        )
        .unwrap();

        let (_, events) = cosmwasm_system_entrypoint::<ExecuteInput, WasmiVM<SimpleWasmiVM>>(
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

mod cw20_ics20 {
    use super::*;
    use ::cw20_ics20::ibc::{Ics20Ack, Ics20Packet};
    use cosmwasm_minimal_std::ibc::{IbcChannelConnectMsg, IbcPacket, IbcPacketReceiveMsg};
    use cosmwasm_vm::{
        executor::ibc::IbcPacketReceiveInput, system::cosmwasm_system_entrypoint_serialize,
    };

    const DEFAULT_TIMEOUT: u64 = 3600;
    const CONTRACT_PORT: &str = "ibc:wasm1234567890abcdef";
    const REMOTE_PORT: &str = "transfer";
    const CONNECTION_ID: &str = "connection-2";
    const ICS20_VERSION: &str = "ics20-1";

    fn forward(x: u64, env: Env) -> Env {
        Env {
            block: BlockInfo {
                height: env.block.height + x,
                time: env.block.time,
                chain_id: env.block.chain_id,
            },
            transaction: env.transaction,
            contract: env.contract,
        }
    }

    fn funded(funds: Vec<Coin>, info: MessageInfo) -> MessageInfo {
        MessageInfo {
            sender: info.sender,
            funds,
        }
    }

    fn create_channel(channel_id: &str) -> IbcChannel {
        IbcChannel {
            endpoint: IbcEndpoint {
                port_id: CONTRACT_PORT.into(),
                channel_id: channel_id.into(),
            },
            counterparty_endpoint: IbcEndpoint {
                port_id: REMOTE_PORT.into(),
                channel_id: format!("{}", channel_id),
            },
            order: IbcOrder::Unordered,
            version: ICS20_VERSION.into(),
            connection_id: CONNECTION_ID.into(),
        }
    }

    fn reverse_channel(channel: IbcChannel) -> IbcChannel {
        IbcChannel {
            endpoint: channel.counterparty_endpoint,
            counterparty_endpoint: channel.endpoint,
            order: channel.order,
            version: channel.version,
            connection_id: channel.connection_id,
        }
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
    fn test_ics20_ibc_orchestration() {
        // State setup
        let code = instrument_contract(include_bytes!("../../fixtures/cw20_ics20.wasm"));
        let sender = BankAccount(100);
        let contract = BankAccount(10_000);
        let funds = vec![];
        let env = Env {
            block: BlockInfo {
                height: 0xDEADC0DE,
                time: Timestamp(10000),
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
            storage: Default::default(),
            codes: BTreeMap::from([(0x1337, code.clone())]),
            contracts: BTreeMap::from([(
                contract,
                CosmwasmContractMeta {
                    code_id: 0x1337,
                    admin: None,
                    label: "".into(),
                },
            )]),
            next_account_id: BankAccount(10_001),
            transaction_depth: 0,
            gas: Gas::new(100_000_000),
            ..Default::default()
        };

        let mut vm = create_vm(&mut extension, env.clone(), info.clone());

        // Contract instantiation
        assert_matches!(
            cosmwasm_system_entrypoint::<InstantiateInput, WasmiVM<SimpleWasmiVM>>(
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

        // IBC channel opening
        let channel_name = "PicassoXTerra";
        let channel = create_channel(channel_name.into());

        assert_matches!(
            cosmwasm_call_serialize::<IbcChannelOpenInput, WasmiVM<SimpleWasmiVM>, _>(
                &mut vm,
                &IbcChannelOpenMsg::OpenInit {
                    channel: channel.clone()
                }
            )
            .unwrap(),
            IbcChannelOpenResult(ContractResult::Ok(None))
        );
        assert_matches!(
            cosmwasm_system_entrypoint_serialize::<IbcChannelConnectInput, WasmiVM<SimpleWasmiVM>, _>(
                &mut vm,
                &IbcChannelConnectMsg::OpenAck {
                    channel: channel.clone(),
                    counterparty_version: ICS20_VERSION.into(),
                },
            ),
            Ok(_)
        );

        // Actual cross-chain execution
        let mut vm = create_vm(
            &mut extension,
            env.clone(),
            funded(
                vec![Coin {
                    denom: "PICA".into(),
                    amount: 1000,
                }],
                info.clone(),
            ),
        );
        assert_matches!(
            cosmwasm_system_entrypoint::<ExecuteInput, WasmiVM<SimpleWasmiVM>>(
                &mut vm,
                format!(
                    r#"{{
                      "transfer": {{
                        "channel": "{}",
                        "remote_address": "0",
                        "timeout": null
                      }}
                    }}"#,
                    channel_name
                )
                .as_bytes(),
            ),
            Ok(_)
        );

        // cw20-ics20 is symmetric, we should be able to forward sent packets
        // back to the contract by reverting the channel/packets
        let (_next_seq, packets_to_dispatch) = extension.ibc.iter().fold(
            (
                0u64,
                Vec::with_capacity(
                    extension
                        .ibc
                        .iter()
                        .map(|(_, x)| x.packets_sent.len())
                        .sum(),
                ),
            ),
            |(next_seq, mut packets_to_dispatch), (_, SimpleIBCState { packets_sent })| {
                packets_sent.iter().enumerate().for_each(
                    |(i, SimpleIBCPacket { data, timeout, .. })| {
                        let packet = serde_json::from_slice::<Ics20Packet>(data.as_ref()).unwrap();
                        packets_to_dispatch.push(IbcPacket {
                            data: Binary::from(
                                serde_json::to_vec(&reverse_packet(channel.clone(), packet))
                                    .unwrap(),
                            ),
                            src: channel.counterparty_endpoint.clone(),
                            dest: channel.endpoint.clone(),
                            sequence: next_seq + i as u64,
                            timeout: timeout.clone(),
                        })
                    },
                );
                (next_seq + packets_sent.len() as u64, packets_to_dispatch)
            },
        );

        let mut vm = create_vm(&mut extension, env.clone(), info.clone());
        for packet in packets_to_dispatch.into_iter() {
            let (acknowledgment, _events) = cosmwasm_system_entrypoint_serialize::<
                IbcPacketReceiveInput,
                WasmiVM<SimpleWasmiVM>,
                _,
            >(&mut vm, &IbcPacketReceiveMsg { packet })
            .unwrap();
            let acknowledgment =
                serde_json::from_slice::<Ics20Ack>(acknowledgment.unwrap().as_ref()).unwrap();
            /*
            Seee `ack_success` in cw20-ics20 ibs.rs

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
