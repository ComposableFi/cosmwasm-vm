extern crate std;

use super::*;
use alloc::string::ToString;
use core::{assert_matches::assert_matches, num::NonZeroU32, str::FromStr};
use cosmwasm_minimal_std::{
    Addr, Attribute, Binary, BlockInfo, Coin, ContractInfo, CosmwasmExecutionResult,
    CosmwasmQueryResult, Empty, Env, Event, InstantiateResult, MessageInfo, QueryResult, Timestamp,
};
use cosmwasm_vm::{
    executor::{cosmwasm_call, ExecuteInput, InstantiateInput, MigrateInput, QueryInput},
    system::{
        cosmwasm_system_entrypoint, cosmwasm_system_run, CosmwasmCodeId, CosmwasmContractMeta,
    },
};
use wasm_instrument::gas_metering::Rules;

pub fn initialize() {
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
    InvalidAccountFormat,
    NoCustomQuery,
    NoCustomMessage,
    Unsupported,
    OutOfGas,
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

#[derive(Clone, PartialEq, Eq, Debug)]
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

struct SimpleWasmiVMExtension {
    storage: BTreeMap<BankAccount, BTreeMap<Vec<u8>, Vec<u8>>>,
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
}

impl<'a> Has<BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<Self>>> for SimpleWasmiVM<'a> {
    fn get(&self) -> BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<Self>> {
        self.host_functions.clone()
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

impl<'a> VMBase for SimpleWasmiVM<'a> {
    type Input<'x> = WasmiInput<'x, WasmiVM<Self>>;
    type Output<'x> = WasmiOutput<'x, WasmiVM<Self>>;
    type QueryCustom = Empty;
    type MessageCustom = Empty;
    type CodeId = CosmwasmContractMeta<BankAccount>;
    type Address = BankAccount;
    type StorageKey = Vec<u8>;
    type StorageValue = Vec<u8>;
    type Error = SimpleVMError;

    fn set_code_id(&mut self, _: Self::Address, _: Self::CodeId) -> Result<(), Self::Error> {
        Err(SimpleVMError::Unsupported)
    }

    fn code_id(&mut self, _: Self::Address) -> Result<Self::CodeId, Self::Error> {
        Err(SimpleVMError::Unsupported)
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
        code_id: Self::CodeId,
        funds: Vec<Coin>,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, Self::Error> {
        let BankAccount(address) = self.extension.next_account_id;
        self.extension.next_account_id = BankAccount(address + 1);
        self.extension
            .contracts
            .insert(BankAccount(address), code_id);
        self.load_subvm(BankAccount(address), funds, |sub_vm| {
            cosmwasm_system_run::<InstantiateInput<Self::MessageCustom>, _>(
                sub_vm,
                message,
                event_handler,
            )
        })?
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

    fn db_read(
        &mut self,
        key: Self::StorageKey,
    ) -> Result<Option<Self::StorageValue>, Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        let empty = BTreeMap::new();
        Ok(self
            .extension
            .storage
            .get(&contract_addr)
            .unwrap_or(&empty)
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
            .or_insert(BTreeMap::new())
            .insert(key, value);
        Ok(())
    }

    fn db_remove(&mut self, key: Self::StorageKey) -> Result<(), Self::Error> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        self.extension
            .storage
            .get_mut(&contract_addr)
            .map(|contract_storage| contract_storage.remove(&key));
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
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
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

fn create_simple_vm<'a>(
    sender: BankAccount,
    address: BankAccount,
    funds: Vec<Coin>,
    code: &[u8],
    extension: &'a mut SimpleWasmiVMExtension,
) -> WasmiVM<SimpleWasmiVM<'a>> {
    initialize();
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
        env: Env {
            block: BlockInfo {
                height: 0xDEADC0DE,
                time: Timestamp(0),
                chain_id: "abstract-test".into(),
            },
            transaction: None,
            contract: ContractInfo {
                address: address.into(),
            },
        },
        info: MessageInfo {
            sender: sender.into(),
            funds,
        },
        extension,
    })
}

#[test]
fn test_bare() {
    let code = instrument_contract(include_bytes!("../../fixtures/cw20_base.wasm"));
    let sender = BankAccount(0);
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
    };
    let mut vm = create_simple_vm(sender, address, funds, &code, &mut extension);
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
fn test_orchestration_base() {
    let code = instrument_contract(include_bytes!("../../fixtures/cw20_base.wasm"));
    let sender = BankAccount(0);
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
    };
    let mut vm = create_simple_vm(sender, address, funds, &code, &mut extension);
    assert_eq!(
        cosmwasm_system_entrypoint::<InstantiateInput, WasmiVM<SimpleWasmiVM>>(
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
        .unwrap(),
        (None, vec![])
    );
    assert_eq!(
        cosmwasm_system_entrypoint::<ExecuteInput, WasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{
              "mint": {
                "recipient": "0xCAFEBABE",
                "amount": "5555"
              }
            }"#
            .as_bytes(),
        )
        .unwrap(),
        (
            None,
            vec![Event::new(
                "wasm".into(),
                vec![
                    Attribute {
                        key: "action".into(),
                        value: "mint".into()
                    },
                    Attribute {
                        key: "to".into(),
                        value: "0xCAFEBABE".into()
                    },
                    Attribute {
                        key: "amount".into(),
                        value: "5555".into()
                    }
                ]
            )]
        )
    );
}

#[test]
fn test_orchestration_advanced() {
    let code = instrument_contract(include_bytes!("../../fixtures/hackatom.wasm"));
    let sender = BankAccount(0);
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
    };
    let mut vm = create_simple_vm(sender, address, funds, &code, &mut extension);
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
    let sender = BankAccount(0);
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
    };
    {
        let mut vm = create_simple_vm(
            address,
            hackatom_address,
            funds.clone(),
            &extension
                .codes
                .get(&extension.contracts.get(&hackatom_address).unwrap().code_id)
                .cloned()
                .unwrap(),
            &mut extension,
        );
        assert_eq!(
            cosmwasm_system_entrypoint::<InstantiateInput, _>(
                &mut vm,
                r#"{"verifier": "10000", "beneficiary": "10000"}"#.as_bytes(),
            )
            .unwrap(),
            (
                None,
                vec![Event {
                    ty: "wasm".into(),
                    attributes: vec![Attribute {
                        key: "Let the".into(),
                        value: "hacking begin".into()
                    }]
                }]
            )
        );
    }
    log::debug!("{:?}", extension.storage);
    {
        let mut vm = create_simple_vm(sender, address, funds, &code, &mut extension);
        assert_eq!(
            cosmwasm_system_entrypoint::<InstantiateInput, WasmiVM<SimpleWasmiVM>>(
                &mut vm,
                r#"{}"#.as_bytes(),
            )
            .unwrap(),
            (None, vec![])
        );
        assert_eq!(
            cosmwasm_system_entrypoint::<ExecuteInput, WasmiVM<SimpleWasmiVM>>(
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
            .unwrap(),
            (
                None,
                vec![
                    Event::new(
                        "wasm".into(),
                        vec![Attribute {
                            key: "action".into(),
                            value: "reflect_subcall".into()
                        },]
                    ),
                    Event::new(
                        "wasm".into(),
                        vec![
                            Attribute {
                                key: "action".into(),
                                value: "release".into()
                            },
                            Attribute {
                                key: "destination".into(),
                                value: "10000".into()
                            },
                        ]
                    ),
                    Event::new(
                        "wasm-hackatom".into(),
                        vec![Attribute {
                            key: "action".into(),
                            value: "release".into()
                        }]
                    )
                ]
            )
        );
    }
}
