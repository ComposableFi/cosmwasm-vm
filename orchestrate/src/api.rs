use crate::vm::{create_vm, Account, Context, Gas, State, VmError};
use cosmwasm_std::{
    Addr, Binary, BlockInfo, Coin, ContractInfo, Env, Event, IbcChannelConnectMsg, IbcPacketAckMsg,
    IbcPacketReceiveMsg, IbcPacketTimeoutMsg, MessageInfo, Timestamp,
};
use cosmwasm_vm::{
    executor::{
        cosmwasm_call,
        ibc::{
            IbcChannelConnectInput, IbcPacketAckInput, IbcPacketReceiveInput, IbcPacketTimeoutInput,
        },
        ExecuteInput, InstantiateInput, QueryInput, QueryResult,
    },
    system::{
        cosmwasm_system_entrypoint, CosmwasmCallVM, CosmwasmCodeId, CosmwasmContractMeta,
        StargateCosmwasmCallVM,
    },
    vm::{VmErrorOf, VmMessageCustomOf},
};
use cosmwasm_vm_wasmi::WasmiVM;
use serde::Serialize;

pub trait Entrypoint {
    type Output<'a>;

    /// Instantiate a contract and get back the contract address and the instantiate result.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `code_id`: Id of code to instantiate a contract from.
    /// * `admin`: Admin of the contract.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `InstantiateMsg`.
    fn instantiate_raw<'a>(
        vm_state: &mut State,
        sender: &Account,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: &[u8],
    ) -> Result<(Account, Self::Output<'a>), VmError> {
        let code_hash = &vm_state
            .codes
            .get(&code_id)
            .ok_or(VmError::CodeNotFound(code_id))?
            .1;
        let contract_addr = Account::generate(code_hash, message);
        Self::instantiate_with_address_raw(
            &contract_addr,
            vm_state,
            sender,
            code_id,
            admin,
            env,
            funds,
            gas,
            message,
        )
    }

    /// Instantiate a contract and get back the contract address and the instantiate result.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `code_id`: Id of code to instantiate a contract from.
    /// * `admin`: Admin of the contract.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Typed message. Possibly `InstantiateMsg` from a contract.
    fn instantiate<'a, M: Serialize>(
        vm_state: &mut State,
        sender: &Account,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: M,
    ) -> Result<(Account, Self::Output<'a>), VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?;
        Self::instantiate_raw(vm_state, sender, code_id, admin, env, funds, gas, &message)
    }

    /// Instantiate a contract and set the contract address to `address`. This should be preferred
    /// if your contract uses a static contract address to execute/query etc.
    ///
    /// * `address`: Instantiated contract's address.
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `code_id`: Id of code to instantiate a contract from.
    /// * `admin`: Admin of the contract.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Typed message. Possibly `InstantiateMsg` from a contract.
    fn instantiate_with_address<'a, M: Serialize>(
        address: &Account,
        vm_state: &mut State,
        sender: &Account,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: M,
    ) -> Result<(Account, Self::Output<'a>), VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?;
        Self::instantiate_with_address_raw(
            address, vm_state, sender, code_id, admin, env, funds, gas, &message,
        )
    }

    /// Instantiate a contract and set the contract address to `address`. This should be preferred
    /// if your contract uses a static contract address to execute/query etc.
    ///
    /// * `address`: Instantiated contract's address.
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `code_id`: Id of code to instantiate a contract from.
    /// * `admin`: Admin of the contract.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `InstantiateMsg`.
    #[allow(clippy::too_many_arguments)]
    fn instantiate_with_address_raw<'a>(
        address: &Account,
        vm_state: &mut State,
        sender: &Account,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        mut env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: &[u8],
    ) -> Result<(Account, Self::Output<'a>), VmError> {
        vm_state.gas = Gas::new(gas);
        if vm_state.db.contracts.contains_key(address) {
            return Err(VmError::AlreadyInstantiated);
        }
        vm_state.db.contracts.insert(
            address.clone(),
            CosmwasmContractMeta {
                code_id,
                admin,
                label: String::from("test-label"),
            },
        );
        vm_state.db.bank.transfer(sender, address, &funds)?;
        env.contract.address = address.clone().into();
        let mut vm = create_vm(
            vm_state,
            env,
            MessageInfo {
                sender: sender.clone().into(),
                funds: funds.clone(),
            },
        );
        match Self::raw_system_call::<InstantiateInput>(&mut vm, message) {
            Ok(output) => Ok((address.clone(), output)),
            Err(e) => {
                vm_state.db.contracts.remove(address);
                Err(e)
            }
        }
    }

    /// Execute a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    fn execute_raw<'a>(
        vm_state: &mut State,
        sender: &Account,
        contract: &Account,
        mut env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: &[u8],
    ) -> Result<Self::Output<'a>, VmError> {
        vm_state.gas = Gas::new(gas);
        vm_state.db.bank.transfer(sender, contract, &funds)?;
        env.contract.address = contract.clone().into();
        let mut vm = create_vm(
            vm_state,
            env,
            MessageInfo {
                sender: sender.clone().into(),
                funds: funds.clone(),
            },
        );
        Self::raw_system_call::<ExecuteInput>(&mut vm, message)
    }

    /// Execute a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Typed message. Possibly `ExecuteMsg` from a contract.
    fn execute<'a, M: Serialize>(
        vm_state: &mut State,
        sender: &Account,
        contract: &Account,
        env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: M,
    ) -> Result<Self::Output<'a>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?;
        Self::execute_raw(vm_state, sender, contract, env, funds, gas, &message)
    }

    /// Initiate an IBC channel handshake.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    fn ibc_channel_connect<'a>(
        vm_state: &mut State,
        sender: Account,
        contract: Account,
        mut env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: IbcChannelConnectMsg,
    ) -> Result<Self::Output<'a>, VmError> {
        vm_state.gas = Gas::new(gas);
        vm_state.db.bank.transfer(&sender, &contract, &funds)?;
        env.contract.address = contract.into();
        let mut vm = create_vm(
            vm_state,
            env,
            MessageInfo {
                sender: sender.into(),
                funds,
            },
        );
        Self::raw_system_call::<IbcChannelConnectInput>(
            &mut vm,
            &serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?,
        )
    }

    /// Receive an IBC packet.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    fn ibc_packet_receive<'a>(
        vm_state: &mut State,
        sender: &Account,
        contract: &Account,
        mut env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: IbcPacketReceiveMsg,
    ) -> Result<Self::Output<'a>, VmError> {
        vm_state.gas = Gas::new(gas);
        vm_state.db.bank.transfer(sender, contract, &funds)?;
        env.contract.address = contract.clone().into();
        let mut vm = create_vm(
            vm_state,
            env,
            MessageInfo {
                sender: sender.clone().into(),
                funds: funds.clone(),
            },
        );
        Self::raw_system_call::<IbcPacketReceiveInput>(
            &mut vm,
            &serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?,
        )
    }

    /// Receive an IBC packet acknowledgement.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    fn ibc_packet_ack<'a>(
        vm_state: &mut State,
        sender: &Account,
        contract: &Account,
        mut env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: IbcPacketAckMsg,
    ) -> Result<Self::Output<'a>, VmError> {
        vm_state.gas = Gas::new(gas);
        vm_state.db.bank.transfer(sender, contract, &funds)?;
        env.contract.address = contract.clone().into();
        let mut vm = create_vm(
            vm_state,
            env,
            MessageInfo {
                sender: sender.clone().into(),
                funds: funds.clone(),
            },
        );
        Self::raw_system_call::<IbcPacketAckInput>(
            &mut vm,
            &serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?,
        )
    }

    /// Receive an IBC packet timeout.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    fn ibc_packet_timeout<'a>(
        vm_state: &mut State,
        sender: &Account,
        contract: &Account,
        mut env: Env,
        funds: Vec<Coin>,
        gas: u64,
        message: IbcPacketTimeoutMsg,
    ) -> Result<Self::Output<'a>, VmError> {
        vm_state.gas = Gas::new(gas);
        vm_state.db.bank.transfer(sender, contract, &funds)?;
        env.contract.address = contract.clone().into();
        let mut vm = create_vm(
            vm_state,
            env,
            MessageInfo {
                sender: sender.clone().into(),
                funds: funds.clone(),
            },
        );
        Self::raw_system_call::<IbcPacketTimeoutInput>(
            &mut vm,
            &serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?,
        )
    }
    /// Query a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `contract`: Contract to be queried.
    /// * `message`: Raw JSON-encoded `QueryMsg`.
    fn query_raw(
        vm_state: &mut State,
        contract: &Account,
        mut env: Env,
        message: &[u8],
    ) -> Result<QueryResult, VmError> {
        env.contract.address = contract.clone().into();
        let mut vm = create_vm(
            vm_state,
            env,
            MessageInfo {
                sender: Addr::unchecked("MOCK_ADDR"),
                funds: vec![],
            },
        );
        cosmwasm_call::<QueryInput, WasmiVM<Context>>(&mut vm, message)
    }

    /// Query a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `contract`: Contract to be queried.
    /// * `message`: Typed message. Possibly `ExecuteMsg` from a contract.
    fn query<M: Serialize>(
        vm_state: &mut State,
        contract: &Account,
        env: Env,
        message: M,
    ) -> Result<QueryResult, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?;
        Self::query_raw(vm_state, contract, env, &message)
    }

    fn raw_system_call<'a, I>(
        vm: &mut WasmiVM<Context>,
        message: &[u8],
    ) -> Result<Self::Output<'a>, VmError>
    where
        for<'x> WasmiVM<Context<'x>>: CosmwasmCallVM<I> + StargateCosmwasmCallVM,
        for<'x> VmErrorOf<WasmiVM<Context<'x>>>: Into<VmError>;
}

pub fn dummy_env() -> Env {
    Env {
        block: BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(10000),
            chain_id: "orchestrate-test".into(),
        },
        transaction: None,
        contract: ContractInfo {
            address: Addr::unchecked("MOCK_ADDR"),
        },
    }
}

/// Calls that are made under this `Unit` type only executes a single
/// entrypoint. It does not execute proceeding sub-messages. One can
/// use this for writing unit tests.
pub struct Unit;

impl Entrypoint for Unit {
    type Output<'a> = cosmwasm_std::ContractResult<
        cosmwasm_std::Response<VmMessageCustomOf<WasmiVM<Context<'a>>>>,
    >;

    fn raw_system_call<'a, I>(
        vm: &mut WasmiVM<Context>,
        message: &[u8],
    ) -> Result<Self::Output<'a>, VmError>
    where
        for<'x> WasmiVM<Context<'x>>: CosmwasmCallVM<I> + StargateCosmwasmCallVM,
        for<'x> VmErrorOf<WasmiVM<Context<'x>>>: Into<VmError>,
    {
        Ok(cosmwasm_call::<I, _>(vm, message)
            .map_err(Into::into)?
            .into())
    }
}

/// Calls that are made under this `Full` type executes the whole flow.
/// It runs the sub-messages as well. One can use this for integration
/// tests.
pub struct Full;

impl Entrypoint for Full {
    type Output<'a> = (Option<Binary>, Vec<Event>);

    fn raw_system_call<'a, I>(
        vm: &mut WasmiVM<Context>,
        message: &[u8],
    ) -> Result<Self::Output<'a>, VmError>
    where
        for<'x> WasmiVM<Context<'x>>: CosmwasmCallVM<I> + StargateCosmwasmCallVM,
        for<'x> VmErrorOf<WasmiVM<Context<'x>>>: Into<VmError>,
    {
        cosmwasm_system_entrypoint::<I, _>(vm, message).map_err(Into::into)
    }
}
