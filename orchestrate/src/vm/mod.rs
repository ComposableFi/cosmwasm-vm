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
use alloc::{string::String, vec, vec::Vec};
use bank::Bank;
use core::{fmt::Debug, num::NonZeroU32};
use cosmwasm_std::{
    Binary, CodeInfoResponse, Coin, ContractInfo, ContractInfoResponse, Env, Event, IbcTimeout,
    MessageInfo, Order, Reply, SystemResult,
};
use cosmwasm_vm::{
    executor::{
        cosmwasm_call, CosmwasmQueryResult, ExecuteCall, InstantiateCall, MigrateCall, QueryCall,
        QueryResult, ReplyCall,
    },
    has::Has,
    system::{cosmwasm_system_run, CosmwasmCodeId, CosmwasmContractMeta, SystemError},
    transaction::Transactional,
    vm::{VMBase, VmErrorOf, VmGas, VmGasCheckpoint},
};
use cosmwasm_vm_wasmi::{
    new_wasmi_vm, OwnedWasmiVM, WasmiContext, WasmiInput, WasmiModule, WasmiOutput, WasmiVMError,
};
use rand_core::SeedableRng;
use serde::de::DeserializeOwned;
use wasm_instrument::gas_metering::Rules;
use wasmi::{Instance, Memory};

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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WasmContractInfo {
    pub instantiator: Account,
    pub code_id: u64,
    pub admin: Option<Account>,
    pub label: String,
}

#[derive(Default, Clone)]
pub struct Db<CH> {
    pub ibc: BTreeMap<IbcChannelId, IbcState>,
    pub contracts: BTreeMap<Account, WasmContractInfo>,
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
    pub executing_module: Option<WasmiModule>,
    pub env: Env,
    pub info: MessageInfo,
    pub state: &'a mut State<CH, AH>,
    call_depth: u32,
}

impl<'a, CH: CustomHandler, AH: AddressHandler> WasmiContext for Context<'a, CH, AH> {
    fn executing_module(&self) -> Option<WasmiModule> {
        self.executing_module.clone()
    }

    fn set_wasmi_context(&mut self, instance: Instance, memory: Memory) {
        self.executing_module = Some(WasmiModule { instance, memory });
    }

    fn call_depth_mut(&mut self) -> &mut u32 {
        &mut self.call_depth
    }
}

impl<'a, CH: CustomHandler, AH: AddressHandler> Context<'a, CH, AH> {
    fn load_subvm<R>(
        &mut self,
        address: <Self as VMBase>::Address,
        funds: Vec<Coin>,
        f: impl FnOnce(&mut OwnedWasmiVM<Context<CH, AH>>) -> R,
    ) -> Result<R, VmErrorOf<Self>> {
        log::debug!(
            "Loading sub-vm {:?} => {:?}",
            self.env.contract.address,
            address
        );
        let WasmContractInfo { code_id, .. } = self
            .state
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
        let mut sub_vm = new_wasmi_vm(
            &code.1,
            Context {
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
                state: self.state,
                call_depth: 0,
            },
        )?;
        Ok(f(&mut sub_vm))
    }

    fn continue_instantiate_impl(
        &mut self,
        CosmwasmContractMeta {
            code_id,
            admin,
            label,
        }: CosmwasmContractMeta<Account>,
        funds: Vec<Coin>,
        message: &[u8],
        salt: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<(Account, Option<Binary>), VmError> {
        let (_, code_hash) = &self
            .state
            .codes
            .get(&code_id)
            .ok_or(VmError::CodeNotFound(code_id))?;
        let address =
            Account::generate::<AH>(&Account(self.env.contract.address.clone()), code_hash, salt)?;

        self.state.db.contracts.insert(
            address.clone(),
            WasmContractInfo {
                instantiator: Account::try_from(self.env.contract.address.clone())
                    .map_err(|_| VmError::InvalidAddress)?,
                code_id,
                admin,
                label,
            },
        );

        self.load_subvm(address.clone(), funds, |sub_vm| {
            cosmwasm_system_run::<InstantiateCall<MessageCustomOf<CH>>, _>(
                sub_vm,
                message,
                event_handler,
            )
        })?
        .map(|data| (address, data))
    }
}

impl<'a, CH: CustomHandler, AH: AddressHandler> VMBase for Context<'a, CH, AH> {
    type Input<'x> = WasmiInput<OwnedWasmiVM<Self>>;
    type Output<'x> = WasmiOutput<OwnedWasmiVM<Self>>;
    type QueryCustom = QueryCustomOf<CH>;
    type MessageCustom = MessageCustomOf<CH>;
    type ContractMeta = CosmwasmContractMeta<Account>;
    type Address = Account;
    type CanonicalAddress = CanonicalAccount;
    type StorageKey = Vec<u8>;
    type StorageValue = Vec<u8>;
    type Error = VmError;

    fn running_contract_meta(&mut self) -> Result<Self::ContractMeta, Self::Error> {
        self.contract_meta(
            Account::try_from(self.env.contract.address.clone()).expect("impossible"),
        )
    }

    fn set_contract_meta(
        &mut self,
        address: Self::Address,
        contract_meta: Self::ContractMeta,
    ) -> Result<(), Self::Error> {
        let mut meta = self
            .state
            .db
            .contracts
            .get_mut(&address)
            .ok_or(VmError::ContractNotFound(address))?;

        meta.code_id = contract_meta.code_id;
        meta.admin = contract_meta.admin;
        meta.label = contract_meta.label;

        Ok(())
    }

    fn contract_meta(&mut self, address: Self::Address) -> Result<Self::ContractMeta, Self::Error> {
        let info = self
            .state
            .db
            .contracts
            .get(&address)
            .cloned()
            .ok_or(VmError::ContractNotFound(address))?;

        Ok(CosmwasmContractMeta {
            code_id: info.code_id,
            admin: info.admin,
            label: info.label,
        })
    }

    fn continue_query(
        &mut self,
        address: Self::Address,
        message: &[u8],
    ) -> Result<QueryResult, Self::Error> {
        self.load_subvm(address, vec![], |sub_vm| {
            cosmwasm_call::<QueryCall, OwnedWasmiVM<Context<CH, AH>>>(sub_vm, message)
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
        contract_meta: CosmwasmContractMeta<Account>,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<(Self::Address, Option<Binary>), Self::Error> {
        self.continue_instantiate_impl(contract_meta, funds, message, b"salt", event_handler)
    }

    fn continue_instantiate2(
        &mut self,
        contract_meta: CosmwasmContractMeta<Account>,
        funds: Vec<Coin>,
        message: &[u8],
        salt: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<(Self::Address, Option<Binary>), Self::Error> {
        self.continue_instantiate_impl(contract_meta, funds, message, salt, event_handler)
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

    fn supply(&mut self, denom: String) -> Result<Coin, Self::Error> {
        log::debug!("Query supply.");
        Ok(Coin::new(self.state.db.bank.supply(&denom), denom))
    }

    fn query_contract_info(
        &mut self,
        contract_address: Self::Address,
    ) -> Result<ContractInfoResponse, Self::Error> {
        let contract_info = self
            .state
            .db
            .contracts
            .get(&contract_address)
            .ok_or(VmError::ContractNotFound(contract_address.clone()))?;
        let mut contract_info_response = ContractInfoResponse::default();
        contract_info_response.code_id = contract_info.code_id;
        contract_info_response.admin = contract_info.admin.clone().map(Into::into);
        contract_info_response.creator = contract_info.instantiator.clone().into();

        let ibc_port_id = contract_address.to_string();
        if self.state.db.ibc.contains_key(&ibc_port_id) {
            contract_info_response.ibc_port = Some(ibc_port_id);
        }

        Ok(contract_info_response)
    }

    fn query_code_info(
        &mut self,
        code_id: CosmwasmCodeId,
    ) -> Result<CodeInfoResponse, Self::Error> {
        let (_, code_hash) = self
            .state
            .codes
            .get(&code_id)
            .ok_or(VmError::CodeNotFound(code_id))?;
        let mut code_info_response = CodeInfoResponse::default();
        code_info_response.code_id = code_id;
        code_info_response.checksum = code_hash.as_slice().into();
        code_info_response.creator = Account::generate_from_seed::<AH>("creator")?.into();
        Ok(code_info_response)
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
        let public_key = libsecp256k1::PublicKey::parse_slice(public_key, None)
            .map_err(|_| VmError::CryptoError)?;
        let message =
            libsecp256k1::Message::parse_slice(message_hash).map_err(|_| VmError::CryptoError)?;
        let mut signature = libsecp256k1::Signature::parse_standard_slice(signature)
            .map_err(|_| VmError::CryptoError)?;
        signature.normalize_s();

        Ok(libsecp256k1::verify(&message, &signature, &public_key))
    }

    fn secp256k1_recover_pubkey(
        &mut self,
        message_hash: &[u8],
        signature: &[u8],
        recovery_param: u8,
    ) -> Result<Result<Vec<u8>, ()>, Self::Error> {
        let message =
            libsecp256k1::Message::parse_slice(message_hash).map_err(|_| VmError::CryptoError)?;
        let signature = libsecp256k1::Signature::parse_standard_slice(signature)
            .map_err(|_| VmError::CryptoError)?;
        let recovery_id =
            libsecp256k1::RecoveryId::parse(recovery_param).map_err(|_| VmError::CryptoError)?;

        Ok(libsecp256k1::recover(&message, &signature, &recovery_id)
            .map(|pubkey| pubkey.serialize().to_vec())
            .map_err(|_| ()))
    }

    fn ed25519_verify(
        &mut self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Self::Error> {
        let signature: [u8; 64] = signature.try_into().map_err(|_| VmError::CryptoError)?;
        let pubkey: [u8; 32] = public_key.try_into().map_err(|_| VmError::CryptoError)?;

        match ed25519_zebra::VerificationKey::try_from(pubkey)
            .and_then(|vk| vk.verify(&ed25519_zebra::Signature::from(signature), message))
        {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn ed25519_batch_verify(
        &mut self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<bool, Self::Error> {
        let messages_len = messages.len();
        let signatures_len = signatures.len();
        let public_keys_len = public_keys.len();

        let mut messages = messages.to_vec();
        let mut public_keys = public_keys.to_vec();
        if messages_len == signatures_len && messages_len == public_keys_len { // We're good to go
        } else if messages_len == 1 && signatures_len == public_keys_len {
            // Replicate message, for multisig
            messages = messages.repeat(signatures_len);
        } else if public_keys_len == 1 && messages_len == signatures_len {
            // Replicate pubkey
            public_keys = public_keys.repeat(messages_len);
        } else {
            return Err(VmError::CryptoError);
        }

        let mut batch = ed25519_zebra::batch::Verifier::new();

        for ((&message, &signature), &public_key) in messages
            .iter()
            .zip(signatures.iter())
            .zip(public_keys.iter())
        {
            // Validation
            let signature: [u8; 64] = signature.try_into().map_err(|_| VmError::CryptoError)?;
            let pubkey: [u8; 32] = public_key.try_into().map_err(|_| VmError::CryptoError)?;

            // Enqueing
            batch.queue((pubkey.into(), signature.into(), message));
        }

        let rng: rand_chacha::ChaChaRng = rand_chacha::ChaChaCore::seed_from_u64(1).into();
        // Batch verification
        match batch.verify(rng) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
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
        self.state.transactions.push(self.state.db.clone());
        log::debug!("> Transaction begin: {}", self.state.transactions.len());
        Ok(())
    }
    fn transaction_commit(&mut self) -> Result<(), Self::Error> {
        let _ = self.state.transactions.pop().expect("impossible");
        log::debug!("< Transaction commit: {}", self.state.transactions.len());
        Ok(())
    }
    fn transaction_rollback(&mut self) -> Result<(), Self::Error> {
        self.state.db = self.state.transactions.pop().expect("impossible");
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

    fn call_per_local_cost(&self) -> u32 {
        0
    }
}
