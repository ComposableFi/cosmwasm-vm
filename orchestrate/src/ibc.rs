use cosmwasm_std::{
    Env, Ibc3ChannelOpenResponse, IbcAcknowledgement, IbcChannel, IbcChannelConnectMsg,
    IbcChannelOpenMsg, IbcEndpoint, IbcOrder, IbcPacketAckMsg, IbcPacketReceiveMsg,
    IbcPacketTimeoutMsg, MessageInfo,
};

use crate::{
    vm::{Account, State, VmError},
    Entrypoint, Full, Unit,
};

pub fn reverse_channel(channel: IbcChannel) -> IbcChannel {
    IbcChannel::new(
        channel.counterparty_endpoint,
        channel.endpoint,
        channel.order,
        channel.version,
        channel.connection_id,
    )
}

pub fn ibc_handshake(
    channel_id: String,
    channel_version: String,
    channel_ordering: IbcOrder,
    connection_id: String,
    state: &mut State,
    state_counterparty: &mut State,
    env: Env,
    env_counterparty: Env,
    info: MessageInfo,
    info_counterparty: MessageInfo,
    gas: u64,
) -> Result<(IbcChannel, IbcChannel), VmError> {
    let contract = Account::try_from(env.contract.address.clone())?;
    let contract_counterparty = Account::try_from(env_counterparty.contract.address.clone())?;
    let mut channel = IbcChannel::new(
        IbcEndpoint {
            port_id: format!("{contract}"),
            channel_id: channel_id.clone(),
        },
        IbcEndpoint {
            port_id: format!("{contract_counterparty}"),
            channel_id: channel_id.clone(),
        },
        channel_ordering,
        channel_version.clone(),
        connection_id,
    );

    // Step 1, OpenInit/Try
    let override_version = Unit::ibc_channel_open(
        state,
        env.clone(),
        info.clone(),
        gas,
        IbcChannelOpenMsg::OpenInit {
            channel: channel.clone(),
        },
    )?
    .0
    .into_result()
    .map_err(|x| VmError::IbcChannelOpenFailure(x))?;

    // The contract may override the channel version.
    match override_version {
        Some(Ibc3ChannelOpenResponse { version }) => channel.version = version,
        None => {}
    }

    let override_version_counterparty = Unit::ibc_channel_open(
        state_counterparty,
        env_counterparty.clone(),
        info_counterparty.clone(),
        gas,
        IbcChannelOpenMsg::OpenTry {
            channel: channel.clone(),
            counterparty_version: channel.version.clone(),
        },
    )?
    .0
    .into_result()
    .map_err(|x| VmError::IbcChannelOpenFailure(x))?;

    // The contract counterparty may override the channel version.
    match override_version_counterparty {
        Some(Ibc3ChannelOpenResponse { version }) => channel.version = version,
        None => {}
    }

    let channel_counterparty = reverse_channel(channel.clone());

    // Step 2, OpenAck/Confirm
    let result = Full::ibc_channel_connect(
        state,
        env,
        info,
        gas,
        IbcChannelConnectMsg::OpenAck {
            channel: channel_counterparty.clone(),
            counterparty_version: channel_counterparty.version.clone(),
        },
    )?;
    log::debug!("Handshake: {:?}", result);
    let result = Full::ibc_channel_connect(
        state_counterparty,
        env_counterparty,
        info_counterparty,
        gas,
        IbcChannelConnectMsg::OpenConfirm {
            channel: channel_counterparty.clone(),
        },
    )?;
    log::debug!("Handshake Counterparty: {:?}", result);
    Ok((channel, channel_counterparty))
}

pub fn ibc_relay_packets(
    channel: IbcChannel,
    state: &mut State,
    state_counterparty: &mut State,
    env: Env,
    env_counterparty: Env,
    info: MessageInfo,
    info_counterparty: MessageInfo,
    gas: u64,
) -> Result<(), VmError> {
    let relayer = Account::try_from(info.sender.clone())?;
    let relayer_counterparty = Account::try_from(info_counterparty.sender.clone())?;
    let channel_state = state
        .db
        .ibc
        .get_mut(&channel.endpoint.channel_id)
        .ok_or(VmError::UnknownIbcChannel)?;
    if channel_state.request_close {
        for packet in channel_state.packets.drain(0..).collect::<Vec<_>>() {
            Full::ibc_packet_timeout(
                state,
                env.clone(),
                info.clone(),
                gas,
                IbcPacketTimeoutMsg::new(
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
        }
    } else {
        for packet in channel_state.packets.drain(0..).collect::<Vec<_>>() {
            log::info!("Relayer: {:?}", packet);
            // TODO: check timeout after env passed as parameter to Full methods
            let (ack, _) = Full::ibc_packet_receive(
                state_counterparty,
                env_counterparty.clone(),
                info_counterparty.clone(),
                gas,
                IbcPacketReceiveMsg::new(
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
            log::info!("Packet ACK: {:?}", ack);
            Full::ibc_packet_ack(
                state,
                env.clone(),
                info.clone(),
                gas,
                IbcPacketAckMsg::new(
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
        }
        // TODO: handle transfers
    }
    Ok(())
}
