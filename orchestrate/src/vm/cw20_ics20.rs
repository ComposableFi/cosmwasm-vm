use cosmwasm_std::{BlockInfo, Coin, Env, IbcChannel, IbcEndpoint, IbcOrder, MessageInfo};
use cw20_ics20_contract::ibc::Ics20Packet;

const CONTRACT_PORT: &str = "ibc:wasm1234567890abcdef";
const REMOTE_PORT: &str = "transfer";
const CONNECTION_ID: &str = "connection-2";
const ICS20_VERSION: &str = "ics20-1";

pub fn forward(x: u64, env: Env) -> Env {
    Env {
        block: BlockInfo {
            height: env.block.height + x,
            time: env.block.time,
            chain_id: env.block.chain_id,
        },
        transaction: env.transaction,
        contract: env.contract,
    }
}

pub fn funded(funds: Vec<Coin>, info: MessageInfo) -> MessageInfo {
    MessageInfo {
        sender: info.sender,
        funds,
    }
}

pub fn create_channel(channel_id: &str) -> IbcChannel {
    IbcChannel::new(
        IbcEndpoint {
            port_id: CONTRACT_PORT.into(),
            channel_id: channel_id.into(),
        },
        IbcEndpoint {
            port_id: REMOTE_PORT.into(),
            channel_id: channel_id.into(),
        },
        IbcOrder::Unordered,
        ICS20_VERSION,
        CONNECTION_ID,
    )
}

pub fn reverse_channel(channel: IbcChannel) -> IbcChannel {
    IbcChannel::new(
        channel.counterparty_endpoint,
        channel.endpoint,
        channel.order,
        channel.version,
        channel.connection_id,
    )
}

pub fn reverse_packet(
    channel: IbcChannel,
    Ics20Packet {
        amount,
        denom,
        receiver,
        sender,
    }: Ics20Packet,
) -> Ics20Packet {
    let reversed_channel = reverse_channel(channel);
    Ics20Packet {
        amount,
        denom: format!(
            "{}/{}/{}",
            reversed_channel.endpoint.port_id, reversed_channel.endpoint.channel_id, denom
        ),
        receiver: sender,
        sender: receiver,
    }
}
