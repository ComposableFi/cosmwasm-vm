use crate::vm::{
    Account, AddressHandler, Context, CustomHandler, IbcChannelId, JunoAddressHandler, State,
    SubstrateAddressHandler, VmError, VmState, WasmAddressHandler,
};
use core::marker::PhantomData;
use cosmwasm_std::{
    from_binary, Addr, Binary, BlockInfo, Coin, ContractInfo, Env, Event, IbcChannelConnectMsg,
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

pub type JunoApi<'a, E = Dispatch> = Api<
    'a,
    E,
    JunoAddressHandler,
    State<(), JunoAddressHandler>,
    Context<'a, (), JunoAddressHandler>,
>;

pub type WasmApi<'a, E = Dispatch> = Api<
    'a,
    E,
    WasmAddressHandler,
    State<(), WasmAddressHandler>,
    Context<'a, (), WasmAddressHandler>,
>;

pub type SubstrateApi<'a, E = Dispatch> = Api<
    'a,
    E,
    SubstrateAddressHandler,
    State<(), SubstrateAddressHandler>,
    Context<'a, (), SubstrateAddressHandler>,
>;

pub struct Api<
    'a,
    E: ExecutionType,
    AH: AddressHandler,
    S: VmState<'a, V> = State<(), AH>,
    V: WasmiBaseVM = Context<'a, (), AH>,
> where
    VmErrorOf<WasmiVM<V>>: Into<VmError>,
{
    _m1: PhantomData<E>,
    _m2: PhantomData<S>,
    _m3: PhantomData<V>,
    _m4: PhantomData<&'a ()>,
    _m5: PhantomData<AH>,
}

impl<'a, E: ExecutionType, AH: AddressHandler, S: VmState<'a, V>, V: WasmiBaseVM>
    Api<'a, E, AH, S, V>
where
    VmErrorOf<WasmiVM<V>>: Into<VmError>,
{
    /// Instantiate a contract and get back the contract address and the
    /// instantiate result.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `code_id`: Id of code to instantiate a contract from.
    /// * `admin`: Admin of the contract.
    /// * `transaction`: `TransactionInfo` to be passed to contract.
    /// * `block`: `BlockInfo` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
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

    /// Instantiate a contract and get back the contract address and the
    /// instantiate result.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `code_id`: Id of code to instantiate a contract from.
    /// * `admin`: Admin of the contract.
    /// * `transaction`: `TransactionInfo` to be passed to contract.
    /// * `block`: `BlockInfo` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
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

    /// Instantiate a contract and set the contract address to
    /// `env.contract.address`. This should be preferred if your contract uses
    /// a static contract address to execute/query etc.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `code_id`: Id of code to instantiate a contract from.
    /// * `admin`: Admin of the contract.
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
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

    /// Instantiate a contract and set the contract address to
    /// `env.contract.address`. This should be preferred if your contract uses
    /// a static contract address to execute/query etc.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `code_id`: Id of code to instantiate a contract from.
    /// * `admin`: Admin of the contract.
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
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
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
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
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
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

    /// Migrate a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn migrate_raw(
        vm_state: &'a mut S,
        code_id: CosmwasmCodeId,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &[u8],
    ) -> Result<E::Output<V>, VmError> {
        vm_state.do_migrate::<E>(code_id, env, info, gas, message)
    }

    /// Migrate a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `code_id`: Id of the code to migrate to.
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Typed message. Possibly `ExecuteMsg` from a contract.
    pub fn migrate<M: Serialize>(
        vm_state: &'a mut S,
        code_id: CosmwasmCodeId,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: M,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotSerialize)?;
        Self::migrate_raw(vm_state, code_id, env, info, gas, &message)
    }

    /// Update admin of a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of this endpoint.
    /// * `contract`: Contract to update admin.
    /// * `new_admin`: New admin to update to.
    pub fn update_admin(
        vm_state: &'a mut S,
        sender: &Account,
        contract_addr: &Account,
        new_admin: Account,
        gas: u64,
    ) -> Result<(), VmError> {
        vm_state.do_update_admin(sender, contract_addr, Some(new_admin), gas)
    }

    /// Clear admin of a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `sender`: Caller of this endpoint.
    /// * `contract`: Contract to update admin.
    /// * `new_admin`: New admin to update to.
    pub fn clear_admin(
        vm_state: &'a mut S,
        sender: &Account,
        contract_addr: &Account,
        gas: u64,
    ) -> Result<(), VmError> {
        vm_state.do_update_admin(sender, contract_addr, None, gas)
    }

    /// Initiate an IBC channel handshake.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn ibc_channel_connect(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &IbcChannelConnectMsg,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_ibc::<E, IbcChannelConnectCall<VmMessageCustomOf<V>>>(env, info, gas, &message)
    }

    /// Receive an IBC packet.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn ibc_packet_receive(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &IbcPacketReceiveMsg,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_ibc::<E, IbcPacketReceiveCall<VmMessageCustomOf<V>>>(env, info, gas, &message)
    }

    /// Receive an IBC packet acknowledgement.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn ibc_packet_ack(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &IbcPacketAckMsg,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_ibc::<E, IbcPacketAckCall<VmMessageCustomOf<V>>>(env, info, gas, &message)
    }

    /// Receive an IBC packet timeout.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `env`: `Env` to be passed to contract.
    /// * `info`: `MessageInfo` to be passed to contract.
    /// * `gas`: Gas limit of this call.
    /// * `message`: Raw JSON-encoded `ExecuteMsg`.
    pub fn ibc_packet_timeout(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &IbcPacketTimeoutMsg,
    ) -> Result<E::Output<V>, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_ibc::<E, IbcPacketTimeoutCall<VmMessageCustomOf<V>>>(env, info, gas, &message)
    }
}

impl<'a, AH: AddressHandler, S: VmState<'a, V>, V: WasmiBaseVM> Api<'a, Direct, AH, S, V>
where
    VmErrorOf<WasmiVM<V>>: Into<VmError>,
{
    /// Query a contract.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `env`: `Env` to be used.
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
    /// * `env`: `Env` to be used.
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

    /// Open an ibc channel.
    ///
    /// * `vm_state`: Shared VM state.
    /// * `env`: `Env` to be used.
    /// * `info`: `MessageInfo` to be used.
    /// * `gas`: Gas limit.
    /// * `message`: Message to pass.
    pub fn ibc_channel_open(
        vm_state: &'a mut S,
        env: Env,
        info: MessageInfo,
        gas: u64,
        message: &IbcChannelOpenMsg,
    ) -> Result<IbcChannelOpenResult, VmError> {
        let message = serde_json::to_vec(&message).map_err(|_| VmError::CannotDeserialize)?;
        vm_state.do_direct::<IbcChannelOpenCall>(env, info, gas, &message)
    }
}

/// Calls that are made by using `Direct` type only executes a single
/// entrypoint. It does not execute proceeding sub-messages. One can
/// use this for writing unit tests.
pub struct Direct;

pub trait ExecutionType {
    type Output<V: WasmiBaseVM>;

    /// Make a call to the contract
    fn raw_system_call<V: WasmiBaseVM, I>(
        vm: &mut WasmiVM<V>,
        message: &[u8],
    ) -> Result<Self::Output<V>, VmError>
    where
        WasmiVM<V>: CosmwasmCallVM<I> + StargateCosmwasmCallVM,
        VmErrorOf<WasmiVM<V>>: Into<VmError>;
}

impl ExecutionType for Direct {
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

/// Calls that are made by using `Dispatch` type executes the whole flow.
/// It runs the sub-messages as well. One can use this for integration
/// tests.
pub struct Dispatch;

impl ExecutionType for Dispatch {
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

/// Convenient builder for `State`
#[derive(Default)]
pub struct StateBuilder<AH: AddressHandler, CH: CustomHandler = ()> {
    codes: Vec<Vec<u8>>,
    balances: Vec<(Account, Coin)>,
    ibc_channels: Vec<IbcChannelId>,
    custom_handler: CH,
    _marker: PhantomData<AH>,
}

impl<CH: CustomHandler + Default, AH: AddressHandler> StateBuilder<AH, CH> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn add_code(mut self, code: &[u8]) -> Self {
        self.codes.push(code.into());
        self
    }

    #[must_use]
    pub fn add_channel(mut self, channel_id: IbcChannelId) -> Self {
        self.ibc_channels.push(channel_id);
        self
    }

    #[must_use]
    pub fn add_balance(mut self, account: Account, coin: Coin) -> Self {
        self.balances.push((account, coin));
        self
    }

    #[must_use]
    pub fn add_codes(mut self, codes: Vec<&[u8]>) -> Self {
        self.codes.extend(codes.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn add_balances(mut self, balances: Vec<(Account, Coin)>) -> Self {
        self.balances.extend(balances.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn set_custom_handler(mut self, custom_handler: CH) -> Self {
        self.custom_handler = custom_handler;
        self
    }

    #[must_use]
    pub fn build(self) -> State<CH, AH> {
        State::new(
            self.codes,
            self.balances,
            self.ibc_channels,
            self.custom_handler,
        )
    }
}

/// Handy function to create a dummy `Block`. Use this
/// if you don't care about any of the fields.
#[must_use]
pub fn block() -> BlockInfo {
    BlockInfo {
        height: 1,
        time: Timestamp::from_seconds(1),
        chain_id: "orchestrate-chain".into(),
    }
}

/// Handy function to create an `Env`. Use this if you only
/// care about the executing contract's address.
///
/// * `contract_addr`: Executing contract's address
#[must_use]
pub fn env(contract_addr: &Account) -> Env {
    Env {
        block: block(),
        transaction: None,
        contract: ContractInfo {
            address: contract_addr.clone().into(),
        },
    }
}

/// Handy function to create a `MessageInfo` without `funds`
#[must_use]
pub fn info(sender: &Account) -> MessageInfo {
    MessageInfo {
        sender: sender.clone().into(),
        funds: vec![],
    }
}
