use super::*;
use alloc::string::ToString;
use core::{assert_matches::assert_matches, str::FromStr};
use cosmwasm_minimal_std::{
    Addr, Attribute, Binary, BlockInfo, Coin, ContractInfo, CosmwasmExecutionResult,
    CosmwasmQueryResult, Empty, Env, Event, InstantiateResult, MessageInfo, QueryResult, Timestamp,
};
use cosmwasm_vm::{
    executor::{cosmwasm_call, cosmwasm_query, ExecuteInput, InstantiateInput, MigrateInput},
    system::{
        cosmwasm_system_entrypoint, cosmwasm_system_run, CosmwasmCodeId, CosmwasmContractMeta,
    },
};

pub fn initialize() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        env_logger::init();
    });
}

#[derive(Debug)]
enum SimpleVMError {
    VMError(WasmiVMError),
    CodeNotFound(CosmwasmCodeId),
    ContractNotFound(BankAccount),
    InvalidAccountFormat,
    NoCustomQuery,
    NoCustomMessage,
    Unsupported,
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
impl HostError for SimpleVMError {}

#[derive(Copy, Clone)]
struct Contract {
    code_id: CosmwasmCodeId,
}

struct SimpleWasmiVMExtension {
    storage: BTreeMap<BankAccount, BTreeMap<Vec<u8>, Vec<u8>>>,
    codes: BTreeMap<CosmwasmCodeId, Vec<u8>>,
    contracts: BTreeMap<BankAccount, Contract>,
    next_account_id: BankAccount,
    transaction_depth: u32,
}

struct SimpleWasmiVM<'a> {
    host_functions_definitions:
        BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<Self>, SimpleVMError>>,
    host_functions:
        BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<AsWasmiVM<Self>, SimpleVMError>>,
    executing_module: WasmiModule,
    env: Env,
    info: MessageInfo,
    extension: &'a mut SimpleWasmiVMExtension,
}

impl<'a> MinWasmiVM<SimpleWasmiVM<'a>> for SimpleWasmiVM<'a> {
    type Error = SimpleVMError;
    fn host_functions_definitions(
        &self,
    ) -> &BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<SimpleWasmiVM<'a>>, SimpleVMError>>
    {
        &self.host_functions_definitions
    }
    fn host_functions(
        &self,
    ) -> &BTreeMap<
        WasmiHostFunctionIndex,
        WasmiHostFunction<AsWasmiVM<SimpleWasmiVM<'a>>, SimpleVMError>,
    > {
        &self.host_functions
    }
    fn module(&self) -> WasmiModule {
        self.executing_module.clone()
    }
}

impl<'a> Host for SimpleWasmiVM<'a> {
    type Key = Vec<u8>;
    type Value = Vec<u8>;
    type QueryCustom = Empty;
    type MessageCustom = Empty;
    type Error = SimpleVMError;

    fn db_read(&mut self, key: Self::Key) -> Result<Option<Self::Value>, HostErrorOf<Self>> {
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

    fn db_write(&mut self, key: Self::Key, value: Self::Value) -> Result<(), HostErrorOf<Self>> {
        let contract_addr = self.env.contract.address.clone().try_into()?;
        self.extension
            .storage
            .entry(contract_addr)
            .or_insert(BTreeMap::new())
            .insert(key, value);
        Ok(())
    }

    fn abort(&mut self, message: String) -> Result<(), HostErrorOf<Self>> {
        log::debug!("Contract aborted: {}", message);
        Err(SimpleVMError::from(WasmiVMError::from(
            SystemError::ContractExecutionFailure(message),
        )))
    }

    fn query_custom(
        &mut self,
        _: Self::QueryCustom,
    ) -> Result<SystemResult<CosmwasmQueryResult>, HostErrorOf<Self>> {
        Err(SimpleVMError::NoCustomQuery)
    }

    fn message_custom(
        &mut self,
        _: Self::MessageCustom,
        _: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, HostErrorOf<Self>> {
        Err(SimpleVMError::NoCustomMessage)
    }

    fn query_raw(
        &mut self,
        address: BankAccountIdOf<Self>,
        key: Self::Key,
    ) -> Result<Option<Self::Value>, HostErrorOf<Self>> {
        Ok(self
            .extension
            .storage
            .get(&address)
            .unwrap_or(&Default::default())
            .get(&key)
            .cloned())
    }

    fn query_info(
        &mut self,
        _: BankAccountIdOf<Self>,
    ) -> Result<cosmwasm_minimal_std::ContractInfoResponse, HostErrorOf<Self>> {
        Err(SimpleVMError::Unsupported)
    }
}

impl<'a> Loader for SimpleWasmiVM<'a> {
    type CodeId = CosmwasmContractMeta;
    type Input = Vec<Coin>;
    type Output = AsWasmiVM<SimpleWasmiVM<'a>>;
    type Error = SimpleVMError;

    fn execution_continuation<I>(
        &mut self,
        address: BankAccountIdOf<Self>,
        input: Self::Input,
        message: &[u8],
        event_handler: &mut dyn FnMut(Event),
    ) -> Result<Option<Binary>, LoaderErrorOf<Self>>
    where
        I: cosmwasm_vm::input::Input,
        I::Output: serde::de::DeserializeOwned
            + cosmwasm_minimal_std::ReadLimit
            + cosmwasm_minimal_std::DeserializeLimit
            + Into<
                cosmwasm_minimal_std::ContractResult<
                    cosmwasm_minimal_std::Response<Self::MessageCustom>,
                >,
            >,
    {
        let code = (|| {
            let Contract { code_id } = self
                .extension
                .contracts
                .get(&address)
                .copied()
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
        let mut sub_vm = AsWasmiVM(SimpleWasmiVM {
            host_functions_definitions: host_functions_definitions.0.clone(),
            host_functions: host_functions_definitions
                .0
                .into_iter()
                .map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
                .flatten()
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
                funds: input,
            },
            extension: self.extension,
        });
        cosmwasm_system_run::<
            MigrateInput<Self::MessageCustom>,
            AsWasmiVM<SimpleWasmiVM>,
            Self::MessageCustom,
        >(&mut sub_vm, message, event_handler)
    }

    fn query_continuation(
        &mut self,
        address: BankAccountIdOf<Self>,
        message: &[u8],
    ) -> Result<QueryResult, LoaderErrorOf<Self>> {
        let code = (|| {
            let Contract { code_id } = self
                .extension
                .contracts
                .get(&address)
                .copied()
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
        let mut sub_vm = AsWasmiVM(SimpleWasmiVM {
            host_functions_definitions: host_functions_definitions.0.clone(),
            host_functions: host_functions_definitions
                .0
                .into_iter()
                .map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
                .flatten()
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
                funds: vec![],
            },
            extension: self.extension,
        });
        cosmwasm_query::<AsWasmiVM<SimpleWasmiVM>>(&mut sub_vm, message)
    }

    fn new(
        &mut self,
        CosmwasmContractMeta { code_id, .. }: Self::CodeId,
    ) -> Result<BankAccountIdOf<Self>, LoaderErrorOf<Self>> {
        let BankAccount(new_account_id) = self.extension.next_account_id;
        self.extension.next_account_id = BankAccount(new_account_id + 1);
        self.extension
            .contracts
            .insert(BankAccount(new_account_id), Contract { code_id });
        Ok(BankAccount(new_account_id))
    }

    fn set_code_id(
        &mut self,
        _: BankAccountIdOf<Self>,
        _: Self::CodeId,
    ) -> Result<(), LoaderErrorOf<Self>> {
        Err(SimpleVMError::Unsupported)
    }

    fn code_id(&mut self, _: BankAccountIdOf<Self>) -> Result<Self::CodeId, LoaderErrorOf<Self>> {
        Err(SimpleVMError::Unsupported)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct BankAccount(u128);

impl<'a> Bank for SimpleWasmiVM<'a> {
    type AccountId = BankAccount;
    type Error = SimpleVMError;
    fn transfer(&mut self, to: &Self::AccountId, funds: &[Coin]) -> Result<(), BankErrorOf<Self>> {
        log::debug!(
            "Transfer: {:?} -> {:?}\n{:?}",
            self.env.contract.address,
            to,
            funds
        );
        Ok(())
    }

    fn burn(&mut self, funds: &[Coin]) -> Result<(), BankErrorOf<Self>> {
        log::debug!("Burn: {:?}\n{:?}", self.env.contract.address, funds);
        Ok(())
    }

    fn query(
        &mut self,
        _: BankQuery,
    ) -> Result<SystemResult<CosmwasmQueryResult>, BankErrorOf<Self>> {
        Err(SimpleVMError::Unsupported)
    }
}

impl TryFrom<Addr> for BankAccount {
    type Error = SimpleVMError;
    fn try_from(value: Addr) -> Result<Self, Self::Error> {
        Ok(value.to_string().try_into()?)
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

impl Into<Addr> for BankAccount {
    fn into(self) -> Addr {
        Addr::unchecked(format!("{}", self.0))
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

fn create_simple_vm<'a>(
    sender: BankAccount,
    address: BankAccount,
    funds: Vec<Coin>,
    code: &[u8],
    extension: &'a mut SimpleWasmiVMExtension,
) -> AsWasmiVM<SimpleWasmiVM<'a>> {
    initialize();
    let host_functions_definitions = WasmiImportResolver(host_functions::definitions());
    let module = new_wasmi_vm(&host_functions_definitions, code).unwrap();
    AsWasmiVM(SimpleWasmiVM {
        host_functions_definitions: host_functions_definitions.0.clone(),
        host_functions: host_functions_definitions
            .0
            .clone()
            .into_iter()
            .map(|(_, modules)| modules.into_iter().map(|(_, function)| function))
            .flatten()
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
    let code = include_bytes!("../../fixtures/cw20_base.wasm").to_vec();
    let sender = BankAccount(0);
    let address = BankAccount(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone())]),
        contracts: BTreeMap::from([(address, Contract { code_id: 0x1337 })]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
    };
    let mut vm = create_simple_vm(sender, address, funds, &code, &mut extension);
    assert_matches!(
        cosmwasm_call::<InstantiateInput<Empty>, AsWasmiVM<SimpleWasmiVM>>(
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
        cosmwasm_query::<AsWasmiVM<SimpleWasmiVM>>(&mut vm, r#"{ "token_info": {} }"#.as_bytes(),)
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
    let code = include_bytes!("../../fixtures/cw20_base.wasm").to_vec();
    let sender = BankAccount(0);
    let address = BankAccount(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone())]),
        contracts: BTreeMap::from([(address, Contract { code_id: 0x1337 })]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
    };
    let mut vm = create_simple_vm(sender, address, funds, &code, &mut extension);
    assert_eq!(
        cosmwasm_system_entrypoint::<InstantiateInput, AsWasmiVM<SimpleWasmiVM>, _>(
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
        cosmwasm_system_entrypoint::<ExecuteInput, AsWasmiVM<SimpleWasmiVM>, _>(
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
    let code = include_bytes!("../../fixtures/hackatom.wasm").to_vec();
    let sender = BankAccount(0);
    let address = BankAccount(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone())]),
        contracts: BTreeMap::from([(address, Contract { code_id: 0x1337 })]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
    };
    let mut vm = create_simple_vm(sender, address, funds, &code, &mut extension);
    assert_eq!(
        cosmwasm_query::<AsWasmiVM<SimpleWasmiVM>>(
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
