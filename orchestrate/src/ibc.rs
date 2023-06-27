use crate::{
    vm::{Account, AddressHandler, Context, CustomHandler, IbcState, State, VmError},
    Api as IApi, Direct, Dispatch,
};
use alloc::{string::String, vec::Vec};
use cosmwasm_std::{
    Binary, Env, Event, Ibc3ChannelOpenResponse, IbcAcknowledgement, IbcChannel,
    IbcChannelConnectMsg, IbcChannelOpenMsg, IbcEndpoint, IbcOrder, IbcPacketAckMsg,
    IbcPacketReceiveMsg, IbcPacketTimeoutMsg, MessageInfo,
};

pub type ConnectionId = String;

#[allow(clippy::module_name_repetitions)]
pub struct IbcNetwork<'a, CH, AH> {
    pub state: &'a mut State<CH, AH>,
    pub state_counterparty: &'a mut State<CH, AH>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IbcHandshakeResult {
    pub data: Option<Binary>,
    pub events: Vec<Event>,
    pub data_counterparty: Option<Binary>,
    pub events_counterparty: Vec<Event>,
    pub channel: IbcChannel,
}

type Api<'a, E, CH, AH> = IApi<'a, E, AH, State<CH, AH>, Context<'a, CH, AH>>;

impl<'a, CH: CustomHandler, AH: AddressHandler> IbcNetwork<'a, CH, AH> {
    pub fn new(state: &'a mut State<CH, AH>, state_counterparty: &'a mut State<CH, AH>) -> Self {
        IbcNetwork {
            state,
            state_counterparty,
        }
    }

    #[must_use]
    pub fn reverse(self) -> Self {
        Self::new(self.state_counterparty, self.state)
    }

    pub fn relay_required(&self, channel: &IbcChannel) -> Result<bool, VmError> {
        ibc_relay_required(channel, self.state)
    }

    pub fn relay<A>(
        &mut self,
        channel: IbcChannel,
        env: Env,
        env_counterparty: Env,
        info: MessageInfo,
        info_counterparty: MessageInfo,
        gas: u64,
        a: &A,
        a_counterparty: &A,
        mut pre: impl FnMut(&mut State<CH, AH>, &mut State<CH, AH>, &A, &A),
        mut post: impl FnMut(
            (Vec<Option<Binary>>, Vec<Event>),
            &mut State<CH, AH>,
            &mut State<CH, AH>,
            &A,
            &A,
        ),
    ) -> Result<(), VmError> {
        pre(self.state, self.state_counterparty, a, a_counterparty);
        let result = ibc_relay::<CH, AH>(
            &channel,
            self.state,
            self.state_counterparty,
            &env,
            &env_counterparty,
            &info,
            &info_counterparty,
            gas,
        )?;
        post(
            result,
            self.state,
            self.state_counterparty,
            a,
            a_counterparty,
        );
        let mut network_reversed = IbcNetwork::new(self.state_counterparty, self.state);
        if network_reversed.relay_required(&channel)? {
            network_reversed.relay::<A>(
                ibc_reverse_channel(channel),
                env_counterparty,
                env,
                info_counterparty,
                info,
                gas,
                a_counterparty,
                a,
                pre,
                post,
            )
        } else {
            Ok(())
        }
    }

    pub fn handshake(
        &mut self,
        channel_id: String,
        channel_version: String,
        channel_ordering: IbcOrder,
        connection_id: String,
        env: Env,
        env_counterparty: Env,
        info: MessageInfo,
        info_counterparty: MessageInfo,
        gas: u64,
    ) -> Result<IbcHandshakeResult, VmError> {
        let contract = Account::try_from(env.contract.address.clone())?;
        let contract_counterparty = Account::try_from(env_counterparty.contract.address.clone())?;
        let mut channel = IbcChannel::new(
            IbcEndpoint {
                port_id: contract.to_string(),
                channel_id: channel_id.clone(),
            },
            IbcEndpoint {
                port_id: contract_counterparty.to_string(),
                channel_id: channel_id.clone(),
            },
            channel_ordering,
            channel_version,
            connection_id,
        );

        // Step 1, OpenInit/Try
        let override_version = Api::<Direct, CH, AH>::ibc_channel_open(
            self.state,
            env.clone(),
            info.clone(),
            gas,
            &IbcChannelOpenMsg::OpenInit {
                channel: channel.clone(),
            },
        )?
        .0
        .into_result()
        .map_err(VmError::IbcChannelOpenFailure)?;

        // The contract may override the channel version.
        if let Some(Ibc3ChannelOpenResponse { version }) = override_version {
            channel.version = version;
        }

        let override_version_counterparty = Api::<Direct, CH, AH>::ibc_channel_open(
            self.state_counterparty,
            env_counterparty.clone(),
            info_counterparty.clone(),
            gas,
            &IbcChannelOpenMsg::OpenTry {
                channel: channel.clone(),
                counterparty_version: channel.version.clone(),
            },
        )?
        .0
        .into_result()
        .map_err(VmError::IbcChannelOpenFailure)?;

        // The contract counterparty may override the channel version.
        if let Some(Ibc3ChannelOpenResponse { version }) = override_version_counterparty {
            channel.version = version;
        }

        let channel_counterparty = ibc_reverse_channel(channel.clone());

        // Step 2, OpenAck/Confirm
        let (data, events) = Api::<Dispatch, CH, AH>::ibc_channel_connect(
            self.state,
            env,
            info,
            gas,
            &IbcChannelConnectMsg::OpenAck {
                channel: channel_counterparty.clone(),
                counterparty_version: channel_counterparty.version.clone(),
            },
        )?;

        let (data_counterparty, events_counterparty) =
            Api::<Dispatch, CH, AH>::ibc_channel_connect(
                self.state_counterparty,
                env_counterparty,
                info_counterparty,
                gas,
                &IbcChannelConnectMsg::OpenConfirm {
                    channel: channel_counterparty,
                },
            )?;

        self.state
            .db
            .ibc
            .insert(channel_id.clone(), IbcState::default());

        self.state_counterparty
            .db
            .ibc
            .insert(channel_id, IbcState::default());

        Ok(IbcHandshakeResult {
            data,
            events,
            data_counterparty,
            events_counterparty,
            channel,
        })
    }
}

#[must_use]
#[allow(clippy::module_name_repetitions)]
pub fn ibc_reverse_channel(channel: IbcChannel) -> IbcChannel {
    IbcChannel::new(
        channel.counterparty_endpoint,
        channel.endpoint,
        channel.order,
        channel.version,
        channel.connection_id,
    )
}

#[allow(clippy::module_name_repetitions)]
pub fn ibc_relay_required<CH: CustomHandler, AH: AddressHandler>(
    channel: &IbcChannel,
    state: &State<CH, AH>,
) -> Result<bool, VmError> {
    let channel_state = state
        .db
        .ibc
        .get(&channel.endpoint.channel_id)
        .ok_or(VmError::UnknownIbcChannel)?;
    Ok(channel_state != &IbcState::default())
}

#[allow(clippy::module_name_repetitions)]
pub fn ibc_relay<CH: CustomHandler, AH: AddressHandler>(
    channel: &IbcChannel,
    state: &mut State<CH, AH>,
    state_counterparty: &mut State<CH, AH>,
    env: &Env,
    env_counterparty: &Env,
    info: &MessageInfo,
    info_counterparty: &MessageInfo,
    gas: u64,
) -> Result<(Vec<Option<Binary>>, Vec<Event>), VmError> {
    let relayer = Account::try_from(info.sender.clone())?;
    let relayer_counterparty = Account::try_from(info_counterparty.sender.clone())?;
    let channel_state = state
        .db
        .ibc
        .get_mut(&channel.endpoint.channel_id)
        .ok_or(VmError::UnknownIbcChannel)?;
    let mut all_events = Vec::new();
    let mut all_data = Vec::new();
    if channel_state.request_close {
        for packet in channel_state.packets.drain(0..).collect::<Vec<_>>() {
            let (data, events) = Api::<Dispatch, CH, AH>::ibc_packet_timeout(
                state,
                env.clone(),
                info.clone(),
                gas,
                &IbcPacketTimeoutMsg::new(
                    cosmwasm_std::IbcPacket::new(
                        packet.data,
                        channel.endpoint.clone(),
                        channel.counterparty_endpoint.clone(),
                        0,
                        packet.timeout,
                    ),
                    relayer.clone().into(),
                ),
            )?;
            all_data.push(data);
            all_events.extend(events);
        }
    } else {
        for packet in channel_state.packets.drain(0..).collect::<Vec<_>>() {
            log::info!("Relaying: {:?}", packet);
            // TODO: check timeout after env passed as parameter to Full methods
            let (ack, events) = Api::<Dispatch, CH, AH>::ibc_packet_receive(
                state_counterparty,
                env_counterparty.clone(),
                info_counterparty.clone(),
                gas,
                &IbcPacketReceiveMsg::new(
                    cosmwasm_std::IbcPacket::new(
                        packet.data.clone(),
                        channel.endpoint.clone(),
                        channel.counterparty_endpoint.clone(),
                        0,
                        packet.timeout.clone(),
                    ),
                    relayer_counterparty.clone().into(),
                ),
            )?;
            all_data.push(ack.clone());
            all_events.extend(events);
            log::info!("Packet ACK: {:?}", ack);
            let (data, events) = Api::<Dispatch, CH, AH>::ibc_packet_ack(
                state,
                env.clone(),
                info.clone(),
                gas,
                &IbcPacketAckMsg::new(
                    IbcAcknowledgement::new(ack.unwrap()),
                    cosmwasm_std::IbcPacket::new(
                        packet.data,
                        channel.endpoint.clone(),
                        channel.counterparty_endpoint.clone(),
                        0,
                        packet.timeout,
                    ),
                    relayer.clone().into(),
                ),
            )?;
            all_data.push(data);
            all_events.extend(events);
        }
        // TODO: handle ics20 transfers?
    }
    Ok((all_data, all_events))
}
