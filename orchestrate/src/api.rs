use crate::vm::VmState;
use crate::vm::{Account, Context, State, VmError};
use core::marker::PhantomData;
use cosmwasm_std::{
    from_binary, Addr, Binary, BlockInfo, ContractInfo, Env, Event, IbcChannelConnectMsg,
    IbcChannelOpenMsg, IbcPacketAckMsg, IbcPacketReceiveMsg, IbcPacketTimeoutMsg, MessageInfo,
    Timestamp, TransactionInfo,
};
use cosmwasm_vm::{
    executor::{
        cosmwasm_call,
        ibc::{
            IbcChannelConnectCall, IbcChannelOpenCall, IbcChannelOpenResult, IbcPacketAckCall,
            IbcPacketReceiveCall, IbcPacketTimeoutCall,
        },
        QueryResult,
    },
    system::{cosmwasm_system_entrypoint, CosmwasmCallVM, CosmwasmCodeId, StargateCosmwasmCallVM},
    vm::{VmErrorOf, VmMessageCustomOf},
};
use cosmwasm_vm_wasmi::{WasmiBaseVM, WasmiVM};
use serde::{de::DeserializeOwned, Serialize};

pub struct Api<'a, E: ExecutionType = Full, S: VmState<'a, V> = State, V: WasmiBaseVM = Context<'a>>
where
    VmErrorOf<WasmiVM<V>>: Into<VmError>,
{
    _m1: PhantomData<E>,
    _m2: PhantomData<S>,
    _m3: PhantomData<V>,
    _m4: PhantomData<&'a ()>,
}

impl<'a, E: ExecutionType, S: VmState<'a, V>, V: WasmiBaseVM> Api<'a, E, S, V>
where
    VmErrorOf<WasmiVM<V>>: Into<VmError>,
{
    /// Instantiate a contract and get back the contract address and the instantiate result.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `code_id`: Id of code to instantiate a contract from.
    /// * `admin`: Admin of the contract.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `InstantiateMsg`.
    pub fn instantiate_raw(
        vm_state: &'a mut S,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        block: BlockInfo,
        transaction: Option<TransactionInfo>,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<(Account, E::Output<V>), VmError> {
        vm_state.do_instantiate::<E>(None, code_id, admin, block, transaction, info, gas, message)
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
    pub fn instantiate<M: Serialize>(
        vm_state: &'a mut S,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        block: BlockInfo,
        transaction: Option<TransactionInfo>,
        info: MessageInfo,
        gas: u64,
        message: M,
    ) -> Result<(Account, E::Output<V>), VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?;
        Self::instantiate_raw(
            vm_state,
            code_id,
            admin,
            block,
            transaction,
            info,
            gas,
            &message,
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
    /// * `message`: Typed message. Possibly `InstantiateMsg` from a contract.
    pub fn instantiate_with_address<M: Serialize>(
        vm_state: &'a mut S,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: M,
    ) -> Result<(Account, E::Output<V>), VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?;
        Self::instantiate_with_address_raw(vm_state, code_id, admin, env, info, gas, &message)
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
    pub fn instantiate_with_address_raw(
        vm_state: &'a mut S,
        code_id: CosmwasmCodeId,
        admin: Option<Account>,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<(Account, E::Output<V>), VmError> {
        vm_state.do_instantiate::<E>(
            Some(env.contract.address.try_into()?),
            code_id,
            admin,
            env.block,
            env.transaction,
            info,
            gas,
            message,
        )
    }

    /// Execute a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn execute_raw(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<E::Output<V>, VmError> {
        vm_state.do_execute::<E>(env, info, gas, message)
    }

    /// Execute a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Typed message. Possibly `ExecuteMsg` from a contract.
    pub fn execute<M: Serialize>(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: M,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?;
        Self::execute_raw(vm_state, env, info, gas, &message)
    }

    /// Initiate an IBC channel handshake.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn ibc_channel_connect(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: IbcChannelConnectMsg,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_ibc::<E, IbcChannelConnectCall<VmMessageCustomOf<V>>>(env, info, gas, &message)
    }

    /// Receive an IBC packet.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn ibc_packet_receive(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: IbcPacketReceiveMsg,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_ibc::<E, IbcPacketReceiveCall<VmMessageCustomOf<V>>>(env, info, gas, &message)
    }

    /// Receive an IBC packet acknowledgement.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn ibc_packet_ack(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: IbcPacketAckMsg,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_ibc::<E, IbcPacketAckCall<VmMessageCustomOf<V>>>(env, info, gas, &message)
    }

    /// Receive an IBC packet timeout.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of the `instantiate` entrypoint.
    /// * `contract`: Contract to be executed.
    /// * `funds`: Assets to send to contract prior to execution.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn ibc_packet_timeout(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: IbcPacketTimeoutMsg,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_ibc::<E, IbcPacketTimeoutCall<VmMessageCustomOf<V>>>(env, info, gas, &message)
    }
}

impl<'a, S: VmState<'a, V>, V: WasmiBaseVM> Api<'a, Unit, S, V>
where
    VmErrorOf<WasmiVM<V>>: Into<VmError>,
{
    /// Query a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `contract`: Contract to be queried.
    /// * `message`: Raw JSON-encoded `QueryMsg`.
    pub fn query_raw(
        vm_state: &'a mut S,
        env: Env,
        message: &[u8],
    ) -> Result<QueryResult, VmError> {
        vm_state.do_query(
            env,
            MessageInfo {
                sender: Addr::unchecked("MOCK_ADDR"),
                funds: vec![],
            },
            message,
        )
    }

    /// Query a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `contract`: Contract to be queried.
    /// * `message`: Typed message. Possibly `ExecuteMsg` from a contract.
    pub fn query<M: Serialize, R: DeserializeOwned>(
        vm_state: &'a mut S,
        env: Env,
        message: M,
    ) -> Result<R, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?;
        let QueryResult(value) = Self::query_raw(vm_state, env, &message)?;
        from_binary::<R>(&value.into_result().map_err(VmError::Generic)?)
            .map_err(|_| VmError::CannotDeserialize)
    }

    pub fn ibc_channel_open(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: IbcChannelOpenMsg,
    ) -> Result<IbcChannelOpenResult, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_direct::<IbcChannelOpenCall>(env, info, gas, &message)
    }
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

pub trait ExecutionType {
    type Output<V: WasmiBaseVM>;

    fn raw_system_call<V: WasmiBaseVM, I>(
        vm: &mut WasmiVM<V>,
        message: &[u8],
    ) -> Result<Self::Output<V>, VmError>
    where
        WasmiVM<V>: CosmwasmCallVM<I> + StargateCosmwasmCallVM,
        VmErrorOf<WasmiVM<V>>: Into<VmError>;
}

impl ExecutionType for Unit {
    type Output<V: WasmiBaseVM> =
        cosmwasm_std::ContractResult<cosmwasm_std::Response<VmMessageCustomOf<WasmiVM<V>>>>;

    fn raw_system_call<V: WasmiBaseVM, I>(
        vm: &mut WasmiVM<V>,
        message: &[u8],
    ) -> Result<Self::Output<V>, VmError>
    where
        WasmiVM<V>: CosmwasmCallVM<I> + StargateCosmwasmCallVM,
        VmErrorOf<WasmiVM<V>>: Into<VmError>,
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

impl ExecutionType for Full {
    type Output<V: WasmiBaseVM> = (Option<Binary>, Vec<Event>);

    fn raw_system_call<V: WasmiBaseVM, I>(
        vm: &mut WasmiVM<V>,
        message: &[u8],
    ) -> Result<Self::Output<V>, VmError>
    where
        WasmiVM<V>: CosmwasmCallVM<I> + StargateCosmwasmCallVM,
        VmErrorOf<WasmiVM<V>>: Into<VmError>,
    {
        cosmwasm_system_entrypoint::<I, _>(vm, message).map_err(Into::into)
    }
}
