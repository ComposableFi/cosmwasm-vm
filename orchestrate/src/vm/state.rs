use super::{
    bank::{self, Bank},
    Account, AddressHandler, Context, CustomHandler, Db, ExecutionType, Gas, IbcChannelId,
    IbcState, VmError,
};
use alloc::collections::{BTreeMap, VecDeque};
use core::fmt::Debug;
use core::marker::PhantomData;
use cosmwasm_std::{BlockInfo, Coin, ContractInfo, Env, MessageInfo, Timestamp, TransactionInfo};
use cosmwasm_vm::{
    executor::{
        cosmwasm_call, CosmwasmCallInput, CosmwasmCallWithoutInfoInput, DeserializeLimit,
        ExecuteCall, HasInfo, InstantiateCall, QueryCall, QueryResult, ReadLimit,
    },
    input::Input,
    memory::PointerOf,
    system::{
        self, CosmwasmCallVM, CosmwasmCodeId, CosmwasmContractMeta, CosmwasmDynamicVM,
        StargateCosmwasmCallVM,
    },
    vm::{VmErrorOf, VmInputOf, VmMessageCustomOf},
};
use cosmwasm_vm_wasmi::{host_functions, new_wasmi_vm, WasmiBaseVM, WasmiImportResolver, WasmiVM};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

#[allow(clippy::module_name_repetitions)]
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

    /// Migrate a contract
    fn do_migrate<E: ExecutionType>(
        &'a mut self,
        code_id: CosmwasmCodeId,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<E::Output<VM>, VmError>;

    /// Update admin of a contract
    fn do_update_admin(
        &'a mut self,
        sender: &Account,
        contract_addr: &Account,
        new_admin: Option<Account>,
        gas: u64,
    ) -> Result<(), VmError>;

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
        WasmiVM<VM>: CosmwasmCallVM<I> + CosmwasmDynamicVM<I> + StargateCosmwasmCallVM;

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

#[derive(Clone)]
pub struct State<CH, AH> {
    pub transactions: VecDeque<Db<CH>>,
    pub db: Db<CH>,
    pub codes: BTreeMap<CosmwasmCodeId, (Vec<u8>, Vec<u8>)>,
    pub gas: Gas,
    _marker: PhantomData<AH>,
}

impl<'a, CH: CustomHandler + Clone, AH: AddressHandler> VmState<'a, Context<'a, CH, AH>>
    for State<CH, AH>
where
    VmErrorOf<WasmiVM<Context<'a, CH, AH>>>: Into<VmError>,
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
    ) -> Result<(Account, E::Output<Context<'a, CH, AH>>), VmError> {
        let contract_addr = if let Some(contract) = contract {
            contract
        } else {
            let (_, code_hash) = self
                .codes
                .get(&code_id)
                .ok_or(VmError::CodeNotFound(code_id))?;
            Account::generate::<AH>(code_hash, message)?
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

        match E::raw_system_call::<
            _,
            InstantiateCall<VmMessageCustomOf<WasmiVM<Context<'a, CH, AH>>>>,
        >(&mut vm, message)
        {
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
    ) -> Result<E::Output<Context<'a, CH, AH>>, VmError> {
        self.gas = Gas::new(gas);
        let mut vm = create_vm(self, env, info);
        E::raw_system_call::<_, ExecuteCall<VmMessageCustomOf<WasmiVM<Context<'a, CH, AH>>>>>(
            &mut vm, message,
        )
    }

    fn do_migrate<E: ExecutionType>(
        &'a mut self,
        code_id: CosmwasmCodeId,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<E::Output<Context<'a, CH, AH>>, VmError> {
        self.gas = Gas::new(gas);

        let contract: Account = env.contract.address.clone().try_into()?;
        let sender: Account = info.sender.clone().try_into()?;
        let mut vm = create_vm(self, env, info);

        let mut meta = vm.contract_meta(contract.clone())?;
        // Only admin can call this entrypoint
        if meta.admin != Some(sender) {
            return Err(VmError::NotAuthorized);
        }
        // Update the `code_id` if necessary
        if meta.code_id != code_id {
            meta.code_id = code_id;
            vm.set_contract_meta(contract, meta)?;
        }
        E::raw_system_call::<_, ExecuteCall<VmMessageCustomOf<WasmiVM<Context<'a, CH, AH>>>>>(
            &mut vm, message,
        )
    }

    fn do_update_admin(
        &'a mut self,
        sender: &Account,
        contract_addr: &Account,
        new_admin: Option<Account>,
        gas: u64,
    ) -> Result<(), VmError> {
        self.gas = Gas::new(gas);
        let env = Env {
            block: BlockInfo {
                height: 0,
                time: Timestamp::from_seconds(1),
                chain_id: String::new(),
            },
            transaction: None,
            contract: ContractInfo {
                address: contract_addr.clone().into(),
            },
        };
        let info = MessageInfo {
            sender: sender.clone().into(),
            funds: vec![],
        };
        let mut vm = create_vm(self, env, info.clone());
        system::update_admin(&mut vm, &info.sender, contract_addr.clone(), new_admin)
    }

    fn do_ibc<E: ExecutionType, I>(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<E::Output<Context<'a, CH, AH>>, VmError>
    where
        WasmiVM<Context<'a, CH, AH>>:
            CosmwasmCallVM<I> + CosmwasmDynamicVM<I> + StargateCosmwasmCallVM,
    {
        self.gas = Gas::new(gas);
        let mut vm = create_vm(self, env, info);
        E::raw_system_call::<Context<'a, CH, AH>, I>(&mut vm, message)
    }

    fn do_query(
        &'a mut self,
        env: Env,
        info: MessageInfo,
        message: &[u8],
    ) -> Result<QueryResult, VmError> {
        let mut vm = create_vm(self, env, info);
        cosmwasm_call::<QueryCall, WasmiVM<Context<CH, AH>>>(&mut vm, message)
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
        for<'x> VmInputOf<'x, WasmiVM<Context<'a, CH, AH>>>: TryFrom<
                CosmwasmCallInput<'x, PointerOf<WasmiVM<Context<'x, CH, AH>>>, I>,
                Error = VmErrorOf<WasmiVM<Context<'a, CH, AH>>>,
            > + TryFrom<
                CosmwasmCallWithoutInfoInput<'x, PointerOf<WasmiVM<Context<'x, CH, AH>>>, I>,
                Error = VmErrorOf<WasmiVM<Context<'a, CH, AH>>>,
            >,
    {
        self.gas = Gas::new(gas);
        let mut vm = create_vm(self, env, info);
        cosmwasm_call::<I, WasmiVM<Context<'a, CH, AH>>>(&mut vm, message)
    }
}

impl<CH: CustomHandler, AH: AddressHandler> Debug for State<CH, AH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("State")
            .field("db", &self.db)
            .field("gas", &self.gas)
            .finish()
    }
}

impl<CH: CustomHandler, AH: AddressHandler> State<CH, AH> {
    #[must_use]
    pub fn new(
        codes: Vec<Vec<u8>>,
        initial_balances: Vec<(Account, Coin)>,
        ibc_channels: Vec<IbcChannelId>,
        custom_handler: CH,
    ) -> Self {
        let mut code_id = 0;
        Self {
            codes: codes
                .into_iter()
                .map(|code| {
                    code_id += 1;
                    let code_hash: Vec<u8> =
                        Sha256::new().chain_update(&code).finalize()[..].into();
                    (code_id, (code_hash, code))
                })
                .collect::<BTreeMap<_, _>>(),
            gas: Gas::new(100_000_000),
            db: Db {
                bank: if initial_balances.is_empty() {
                    Bank::default()
                } else {
                    let mut supply = bank::Supply::new();
                    let mut balances = bank::Balances::new();
                    for (account, coin) in initial_balances {
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
                    }
                    Bank::new(supply, balances)
                },
                ibc: ibc_channels
                    .into_iter()
                    .map(|x| (x, IbcState::default()))
                    .collect(),
                custom_handler,
                ..Default::default()
            },
            transactions: VecDeque::default(),
            _marker: PhantomData,
        }
    }
}

fn create_vm<CH: CustomHandler, AH: AddressHandler>(
    extension: &mut State<CH, AH>,
    env: Env,
    info: MessageInfo,
) -> WasmiVM<Context<CH, AH>> {
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
            .flat_map(|(_, modules)| modules.into_values())
            .collect(),
        executing_module: module,
        env,
        info,
        state: extension,
    })
}
