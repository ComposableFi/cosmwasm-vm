use super::validation::ExportRequirement;
use cosmwasm_vm::executor::{
    ibc::{
        IbcChannelCloseCall, IbcChannelConnectCall, IbcChannelOpenCall, IbcPacketAckCall,
        IbcPacketReceiveCall, IbcPacketTimeoutCall,
    },
    AllocateCall, AsFunctionName, DeallocateCall, ExecuteCall, InstantiateCall, MigrateCall,
    QueryCall, ReplyCall,
};
use wasm_instrument::parity_wasm::elements::ValueType;

/// Requirement, Export name, Parameters
pub type Export = (ExportRequirement, &'static str, &'static [ValueType]);

pub trait Version {
    /// `ENV_MODULE.ENV_GAS` function import should be injected by the instrumentor.
    const ENV_MODULE: &'static str = "env";
    const ENV_GAS: &'static str = "gas";
    const EXPORTS: &'static [Export];
    const IBC_EXPORTS: &'static [Export];
}

#[allow(clippy::module_name_repetitions)]
pub struct Version1x;

impl Version for Version1x {
    const EXPORTS: &'static [Export] = &[
        // We support v1+
        (
            ExportRequirement::Mandatory,
            // extern "C" fn interface_version_8() -> () {}
            "interface_version_8",
            &[],
        ),
        // Memory related exports.
        (
            ExportRequirement::Mandatory,
            // extern "C" fn allocate(size: usize) -> u32;
            AllocateCall::<()>::NAME,
            &[ValueType::I32],
        ),
        (
            ExportRequirement::Mandatory,
            // extern "C" fn deallocate(pointer: u32);
            DeallocateCall::<()>::NAME,
            &[ValueType::I32],
        ),
        // Contract execution exports.
        (
            ExportRequirement::Mandatory,
            // extern "C" fn instantiate(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32;
            InstantiateCall::<()>::NAME,
            &[ValueType::I32, ValueType::I32, ValueType::I32],
        ),
        (
            ExportRequirement::Optional,
            // extern "C" fn execute(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32;
            ExecuteCall::<()>::NAME,
            &[ValueType::I32, ValueType::I32, ValueType::I32],
        ),
        (
            ExportRequirement::Optional,
            // extern "C" fn query(env_ptr: u32, msg_ptr: u32) -> u32;
            QueryCall::NAME,
            &[ValueType::I32, ValueType::I32],
        ),
        (
            ExportRequirement::Optional,
            // extern "C" fn migrate(env_ptr: u32, msg_ptr: u32) -> u32;
            MigrateCall::<()>::NAME,
            &[ValueType::I32, ValueType::I32],
        ),
        (
            ExportRequirement::Optional,
            // extern "C" fn reply(env_ptr: u32, msg_ptr: u32) -> u32;
            ReplyCall::<()>::NAME,
            &[ValueType::I32, ValueType::I32],
        ),
    ];

    // IBC callbacks that a contract must export to be considered IBC capable:
    // extern "C" fn ibc_channel_open(env_ptr: u32, msg_ptr: u32) -> u32;
    // extern "C" fn ibc_channel_connect(env_ptr: u32, msg_ptr: u32) -> u32;
    // extern "C" fn ibc_channel_close(env_ptr: u32, msg_ptr: u32) -> u32;
    // extern "C" fn ibc_packet_receive(env_ptr: u32, msg_ptr: u32) -> u32;
    // extern "C" fn ibc_packet_ack(env_ptr: u32, msg_ptr: u32) -> u32;
    // extern "C" fn ibc_packet_timeout(env_ptr: u32, msg_ptr: u32) -> u32;
    const IBC_EXPORTS: &'static [Export] = &[
        (
            ExportRequirement::Mandatory,
            IbcChannelOpenCall::NAME,
            &[ValueType::I32, ValueType::I32],
        ),
        (
            ExportRequirement::Mandatory,
            IbcChannelConnectCall::<()>::NAME,
            &[ValueType::I32, ValueType::I32],
        ),
        (
            ExportRequirement::Mandatory,
            IbcChannelCloseCall::<()>::NAME,
            &[ValueType::I32, ValueType::I32],
        ),
        (
            ExportRequirement::Mandatory,
            IbcPacketReceiveCall::<()>::NAME,
            &[ValueType::I32, ValueType::I32],
        ),
        (
            ExportRequirement::Mandatory,
            IbcPacketAckCall::<()>::NAME,
            &[ValueType::I32, ValueType::I32],
        ),
        (
            ExportRequirement::Mandatory,
            IbcPacketTimeoutCall::<()>::NAME,
            &[ValueType::I32, ValueType::I32],
        ),
    ];
}
