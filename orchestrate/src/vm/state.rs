use super::{
    bank::{self, Bank},
    Account, Context, Db, ExecutionType, Gas, IbcChannelId, IbcState, VmError,
};
use alloc::collections::{BTreeMap, VecDeque};
use core::fmt::Debug;
use cosmwasm_std::{BlockInfo, Coin, ContractInfo, Env, MessageInfo, TransactionInfo};
use cosmwasm_vm::{
    executor::{
        cosmwasm_call, CosmwasmCallInput, CosmwasmCallWithoutInfoInput, DeserializeLimit,
        ExecuteCall, HasInfo, InstantiateCall, QueryCall, QueryResult, ReadLimit,
    },
    input::Input,
    memory::PointerOf,
    system::{CosmwasmCallVM, CosmwasmCodeId, CosmwasmContractMeta, StargateCosmwasmCallVM},
    vm::{VmErrorOf, VmInputOf},
};
use cosmwasm_vm_wasmi::{host_functions, new_wasmi_vm, WasmiBaseVM, WasmiImportResolver, WasmiVM};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

pub trait VmState<'a, VM: WasmiBaseVM>
where
    VmErrorOf<WasmiVM<VM>>: Into<VmError>,
{
    /// Instantiate a contract
    /// If `contract` is `None`, implementors should generate an address
    fn do_instantiate<E: ExecutionType>(
        &'a mut self,
        contract: Option<Account>,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        block: BlockInfo,
        transaction: Option<TransactionInfo>,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<(Account, E::Output<VM>), VmError>;

    /// Execute a contract
    fn do_execute<E: ExecutionType>(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<E::Output<VM>, VmError>;

    /// Query a contract
    fn do_query(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        message: &[u8],
    ) -> Result<QueryResult, VmError>;

    /// Common endpoint for calling all dispatchable ibc entrypoints
    fn do_ibc<E: ExecutionType, I>(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<E::Output<VM>, VmError>
    where
        WasmiVM<VM>: CosmwasmCallVM<I> + StargateCosmwasmCallVM;

    /// Common endpoint for any other direct endpoint like `ibc_channel_open`
    fn do_direct<I>(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<I::Output, VmError>
    where
        I: Input + HasInfo,
        I::Output: DeserializeOwned + ReadLimit + DeserializeLimit,
        for<'x> VmInputOf<'x, WasmiVM<VM>>: TryFrom<
                CosmwasmCallInput<'x, PointerOf<WasmiVM<VM>>, I>,
                Error = VmErrorOf<WasmiVM<VM>>,
            > + TryFrom<
                CosmwasmCallWithoutInfoInput<'x, PointerOf<WasmiVM<VM>>, I>,
                Error = VmErrorOf<WasmiVM<VM>>,
            >;
}

#[derive(Default, Clone)]
pub struct State {
    pub transactions: VecDeque<Db>,
    pub db: Db,
    pub codes: BTreeMap<CosmwasmCodeId, (Vec<u8>, Vec<u8>)>,
    pub gas: Gas,
}

impl<'a> VmState<'a, Context<'a>> for State
where
    VmErrorOf<WasmiVM<Context<'a>>>: Into<VmError>,
{
    fn do_instantiate<E: ExecutionType>(
        &'a mut self,
        contract: Option<Account>,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        block: BlockInfo,
        transaction: Option<TransactionInfo>,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<(Account, E::Output<Context<'a>>), VmError> {
        let contract_addr = match contract {
            Some(contract) => contract,
            None => {
                let (_, code_hash) = self
                    .codes
                    .get(&code_id)
                    .ok_or(VmError::CodeNotFound(code_id))?;
                Account::generate(code_hash, message)
            }
        };
        self.gas = Gas::new(gas);
        if self.db.contracts.contains_key(&contract_addr) {
            return Err(VmError::AlreadyInstantiated);
        }
        self.db.contracts.insert(
            contract_addr.clone(),
            CosmwasmContractMeta {
                code_id,
                admin,
                label: String::from("test-label"),
            },
        );
        let mut vm = create_vm(
            self,
            Env {
                block,
                transaction,
                contract: ContractInfo {
                    address: contract_addr.clone().into(),
                },
            },
            info,
        );

        match E::raw_system_call::<_, InstantiateCall>(&mut vm, message) {
            Ok(output) => Ok((contract_addr, output)),
            Err(e) => {
                vm.0.state.db.contracts.remove(&contract_addr);
                Err(e)
            }
        }
    }

    fn do_execute<E: ExecutionType>(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<E::Output<Context<'a>>, VmError> {
        self.gas = Gas::new(gas);
        let mut vm = create_vm(self, env, info);
        E::raw_system_call::<Context<'a>, ExecuteCall>(&mut vm, message)
    }

    fn do_ibc<E: ExecutionType, I>(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<E::Output<Context<'a>>, VmError>
    where
        WasmiVM<Context<'a>>: CosmwasmCallVM<I> + StargateCosmwasmCallVM,
    {
        self.gas = Gas::new(gas);
        let mut vm = create_vm(self, env, info);
        E::raw_system_call::<Context<'a>, I>(&mut vm, message)
    }

    fn do_query(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        message: &[u8],
    ) -> Result<QueryResult, VmError> {
        let mut vm = create_vm(self, env, info);
        cosmwasm_call::<QueryCall, WasmiVM<Context>>(&mut vm, message)
    }

    fn do_direct<I>(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<I::Output, VmError>
    where
        I: Input + HasInfo,
        I::Output: DeserializeOwned + ReadLimit + DeserializeLimit,
        for<'x> VmInputOf<'x, WasmiVM<Context<'a>>>: TryFrom<
                CosmwasmCallInput<'x, PointerOf<WasmiVM<Context<'x>>>, I>,
                Error = VmErrorOf<WasmiVM<Context<'a>>>,
            > + TryFrom<
                CosmwasmCallWithoutInfoInput<'x, PointerOf<WasmiVM<Context<'x>>>, I>,
                Error = VmErrorOf<WasmiVM<Context<'a>>>,
            >,
    {
        self.gas = Gas::new(gas);
        let mut vm = create_vm(self, env, info);
        cosmwasm_call::<I, WasmiVM<Context<'a>>>(&mut vm, message)
    }
}

impl Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("State")
            .field("db", &self.db)
            .field("gas", &self.gas)
            .finish()
    }
}

impl State {
    pub fn new(
        codes: Vec<Vec<u8>>,
        initial_balances: Vec<(Account, Coin)>,
        ibc_channels: Vec<IbcChannelId>,
    ) -> Self {
        let mut code_id = 0;
        Self {
            codes: BTreeMap::from_iter(codes.into_iter().map(|code| {
                code_id += 1;
                let code_hash: Vec<u8> = Sha256::new().chain_update(&code).finalize()[..].into();
                (code_id, (code_hash, code))
            })),
            gas: Gas::new(100_000_000),
            db: Db {
                bank: if !initial_balances.is_empty() {
                    let mut supply = bank::Supply::new();
                    let mut balances = bank::Balances::new();
                    initial_balances.into_iter().for_each(|(account, coin)| {
                        supply
                            .entry(coin.denom.clone())
                            .and_modify(|amount| *amount += Into::<u128>::into(coin.amount))
                            .or_insert_with(|| coin.amount.into());
                        balances
                            .entry(account)
                            .and_modify(|coins| {
                                coins
                                    .entry(coin.denom.clone())
                                    .and_modify(|amount| *amount += Into::<u128>::into(coin.amount))
                                    .or_insert_with(|| (coin.amount.into()));
                            })
                            .or_insert_with(|| [(coin.denom, coin.amount.into())].into());
                    });
                    Bank::new(supply, balances)
                } else {
                    Default::default()
                },
                ibc: ibc_channels
                    .into_iter()
                    .map(|x| (x, IbcState::default()))
                    .collect(),
                ..Default::default()
            },
            transactions: Default::default(),
        }
    }
}

fn create_vm(extension: &mut State, env: Env, info: MessageInfo) -> WasmiVM<Context> {
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
