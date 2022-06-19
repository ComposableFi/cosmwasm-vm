use super::*;
use alloc::{rc::Rc, string::ToString};
use core::{
    assert_matches::assert_matches,
    cell::{BorrowError, BorrowMutError, RefCell},
    str::FromStr,
};
use cosmwasm_minimal_std::{
    Addr, Attribute, Binary, BlockInfo, Coin, ContractInfo, CosmwasmExecutionResult,
    CosmwasmQueryResult, Empty, Env, Event, InstantiateResult, MessageInfo, QueryResult, Timestamp,
};
use cosmwasm_vm::{
    executor::{cosmwasm_call, cosmwasm_query, ExecuteInput, InstantiateInput},
    system::{cosmwasm_system_entrypoint, CosmwasmCodeId, CosmwasmNewContract},
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
    Borrow(BorrowError),
    BorrowMut(BorrowMutError),
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
impl From<BorrowMutError> for SimpleVMError {
    fn from(e: BorrowMutError) -> Self {
        SimpleVMError::BorrowMut(e)
    }
}
impl From<BorrowError> for SimpleVMError {
    fn from(e: BorrowError) -> Self {
        SimpleVMError::Borrow(e)
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
    storage: BTreeMap<Vec<u8>, Vec<u8>>,
    codes: BTreeMap<CosmwasmCodeId, Vec<u8>>,
    contracts: BTreeMap<BankAccount, Contract>,
    next_account_id: BankAccount,
    transaction_depth: u32,
}

struct SimpleWasmiVM {
    host_functions_definitions:
        BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<Self>, SimpleVMError>>,
    host_functions:
        BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<AsWasmiVM<Self>, SimpleVMError>>,
    executing_module: WasmiModule,
    env: Env,
    info: MessageInfo,
    extension: Rc<RefCell<SimpleWasmiVMExtension>>,
}

impl MinWasmiVM<SimpleWasmiVM> for SimpleWasmiVM {
    type Error = SimpleVMError;
    fn host_functions_definitions(
        &self,
    ) -> &BTreeMap<WasmiModuleName, WasmiHostModule<AsWasmiVM<SimpleWasmiVM>, SimpleVMError>> {
        &self.host_functions_definitions
    }
    fn host_functions(
        &self,
    ) -> &BTreeMap<WasmiHostFunctionIndex, WasmiHostFunction<AsWasmiVM<SimpleWasmiVM>, SimpleVMError>>
    {
        &self.host_functions
    }
    fn module(&self) -> WasmiModule {
        self.executing_module.clone()
    }
}

impl Host for SimpleWasmiVM {
    type Key = Vec<u8>;
    type Value = Vec<u8>;
    type QueryCustom = Empty;
    type MessageCustom = Empty;
    type Error = SimpleVMError;

    fn db_read(&mut self, key: Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        Ok(self.extension.try_borrow()?.storage.get(&key).cloned())
    }

    fn db_write(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.extension.try_borrow_mut()?.storage.insert(key, value);
        Ok(())
    }

    fn abort(&mut self, message: String) -> Result<(), Self::Error> {
        log::debug!("Contract aborted: {}", message);
        Err(SimpleVMError::from(WasmiVMError::from(
            SystemError::ContractExecutionFailure(message),
        )))
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
}

impl WasmiHost for SimpleWasmiVM {}

impl Loader for SimpleWasmiVM {
    type CodeId = CosmwasmNewContract;
    type Address = BankAccount;
    type Input = Vec<Coin>;
    type Output = AsWasmiVM<SimpleWasmiVM>;
    type Error = SimpleVMError;

    fn load(
        &mut self,
        address: Self::Address,
        funds: Self::Input,
    ) -> Result<Self::Output, Self::Error> {
        log::debug!("Load");
        let ext = self.extension.try_borrow()?;
        let Contract { code_id } = ext
            .contracts
            .get(&address)
            .copied()
            .ok_or(SimpleVMError::ContractNotFound(address))?;
        let code = ext
            .codes
            .get(&code_id)
            .ok_or(SimpleVMError::CodeNotFound(code_id))?;
        new_vm(
            &code,
            self.extension.clone(),
            |WasmiImportResolver(host_functions_definitions), _, extension, module| SimpleWasmiVM {
                host_functions_definitions: host_functions_definitions.clone(),
                host_functions: host_functions_definitions
                    .clone()
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
                    funds,
                },
                extension,
            },
        )
    }

    fn new(
        &mut self,
        CosmwasmNewContract { code_id, .. }: Self::CodeId,
    ) -> Result<Self::Address, Self::Error> {
        let mut ext = self.extension.try_borrow_mut()?;
        let BankAccount(new_account_id) = ext.next_account_id;
        ext.next_account_id = BankAccount(new_account_id + 1);
        ext.contracts
            .insert(BankAccount(new_account_id), Contract { code_id });
        Ok(BankAccount(new_account_id))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct BankAccount(u128);

impl Bank for SimpleWasmiVM {
    type AccountId = BankAccount;
    type Error = SimpleVMError;
    fn transfer(&mut self, to: &Self::AccountId, funds: &[Coin]) -> Result<(), Self::Error> {
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

    fn query(&mut self, _: BankQuery) -> Result<SystemResult<CosmwasmQueryResult>, Self::Error> {
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

impl Has<Env> for SimpleWasmiVM {
    fn get(&self) -> Env {
        self.env.clone()
    }
}
impl Has<MessageInfo> for SimpleWasmiVM {
    fn get(&self) -> MessageInfo {
        self.info.clone()
    }
}

impl Transactional for SimpleWasmiVM {
    type Error = SimpleVMError;
    fn transaction_begin(&mut self) -> Result<(), Self::Error> {
        let mut ext = self.extension.try_borrow_mut()?;
        ext.transaction_depth += 1;
        log::debug!("> Transaction begin: {}", ext.transaction_depth);
        Ok(())
    }
    fn transaction_commit(&mut self) -> Result<(), Self::Error> {
        let mut ext = self.extension.try_borrow_mut()?;
        ext.transaction_depth -= 1;
        log::debug!("< Transaction end: {}", ext.transaction_depth);
        Ok(())
    }
    fn transaction_rollback(&mut self) -> Result<(), Self::Error> {
        let mut ext = self.extension.try_borrow_mut()?;
        ext.transaction_depth -= 1;
        log::debug!("< Transaction abort: {}", ext.transaction_depth);
        Ok(())
    }
}

fn create_simple_vm(
    sender: BankAccount,
    address: BankAccount,
    funds: Vec<Coin>,
    code: &[u8],
    extension: Rc<RefCell<SimpleWasmiVMExtension>>,
) -> AsWasmiVM<SimpleWasmiVM> {
    initialize();
    new_vm::<SimpleWasmiVM, _>(
        code,
        extension,
        |WasmiImportResolver(host_functions_definitions), _, extension, module| SimpleWasmiVM {
            host_functions_definitions: host_functions_definitions.clone(),
            host_functions: host_functions_definitions
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
        },
    )
    .unwrap()
}

fn test_bare() {
    let code = include_bytes!("../../fixtures/cw20_base.wasm").to_vec();
    let sender = BankAccount(0);
    let address = BankAccount(10_000);
    let funds = vec![];
    let extension = Rc::new(RefCell::new(SimpleWasmiVMExtension {
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone())]),
        contracts: BTreeMap::from([(address, Contract { code_id: 0x1337 })]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
    }));
    let mut vm = create_simple_vm(sender, address, funds, &code, extension);
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

fn test_orchestration_base() {
    let code = include_bytes!("../../fixtures/cw20_base.wasm").to_vec();
    let sender = BankAccount(0);
    let address = BankAccount(10_000);
    let funds = vec![];
    let extension = Rc::new(RefCell::new(SimpleWasmiVMExtension {
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone())]),
        contracts: BTreeMap::from([(address, Contract { code_id: 0x1337 })]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
    }));
    let mut vm = create_simple_vm(sender, address, funds, &code, extension);
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
    let extension = Rc::new(RefCell::new(SimpleWasmiVMExtension {
        storage: Default::default(),
        codes: BTreeMap::from([(0x1337, code.clone())]),
        contracts: BTreeMap::from([(address, Contract { code_id: 0x1337 })]),
        next_account_id: BankAccount(10_001),
        transaction_depth: 0,
    }));
    let mut vm = create_simple_vm(sender, address, funds, &code, extension);
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
