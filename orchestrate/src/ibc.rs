use cosmwasm_std::{
    Coin, IbcChannel, IbcChannelConnectMsg, IbcEndpoint, IbcOrder, IbcPacketReceiveMsg,
    IbcPacketTimeoutMsg,
};

use crate::{
    vm::{Account, State, VmError},
    Entrypoint, Full,
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
    contract: Account,
    contract_counterparty: Account,
    relayer: Account,
    funds: Vec<Coin>,
    gas: u64,
) -> Result<(IbcChannel, IbcChannel), VmError> {
    let channel = IbcChannel::new(
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
    let channel_counterparty = reverse_channel(channel.clone());
    // TODO: channel open
    let result = Full::ibc_channel_connect(
        state,
        relayer.clone(),
        contract,
        funds.clone(),
        gas,
        IbcChannelConnectMsg::OpenAck {
            channel: channel.clone(),
            counterparty_version: channel_version,
        },
    )?;
    log::debug!("Handshake: {:?}", result);
    let result = Full::ibc_channel_connect(
        state_counterparty,
        relayer,
        contract_counterparty,
        funds,
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
    contract: Account,
    contract_counterparty: Account,
    relayer: Account,
    funds: Vec<Coin>,
    gas: u64,
) -> Result<(), VmError> {
    let channel_state = state
        .db
        .ibc
        .get_mut(&channel.endpoint.channel_id)
        .ok_or(VmError::UnknownIbcChannel)?;
    if channel_state.request_close {
        for packet in channel_state.packets.drain(0..).collect::<Vec<_>>() {
            Full::ibc_packet_timeout(
                state,
                &relayer,
                &contract,
                funds.clone(),
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
        for packet in channel_state.packets.drain(0..) {
            // TODO: check timeout after env passed as parameter to Full methods
            Full::ibc_packet_receive(
                state_counterparty,
                &relayer,
                &contract_counterparty,
                funds.clone(),
                gas,
                IbcPacketReceiveMsg::new(
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
