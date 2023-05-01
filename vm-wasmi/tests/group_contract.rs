#![feature(assert_matches)]

mod helpers;
use helpers::run_test_with_init;

use cosmwasm_std::{Binary, ContractResult};
use cosmwasm_vm::executor::{cosmwasm_call, QueryCall};
use cosmwasm_vm_wasmi::{OwnedWasmiVM, SimpleVMError, SimpleWasmiVM};

use cw4::Member;
use cw4_group::msg::InstantiateMsg;
use cw4_group::msg::QueryMsg;

const ADMIN: &str = "0000";
const USER1: &str = "1000";
const USER2: &str = "2000";
const USER3: &str = "3000";

const BYTECODES: &[(&str, &[u8])] = &[
    (
        "self-built",
        include_bytes!("../../cw-plus/target/wasm32-unknown-unknown/release/cw4_group.wasm"),
    ),
    ("official", include_bytes!("../../fixtures/cw4_group.wasm")),
];

#[test]
fn empty_group() -> Result<(), Box<dyn std::error::Error>> {
    run_test_with_init(
        BYTECODES,
        InstantiateMsg {
            admin: None,
            members: vec![],
        },
        |vm| {
            if let ContractResult::<Binary>::Ok(binary) =
                cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(
                    vm,
                    r#"{ "total_weight": {} }"#.as_bytes(),
                )?
                .0
            {
                assert_eq!(binary, Binary(r#"{"weight":0}"#.as_bytes().to_vec()));
                Ok(())
            } else {
                // stand-in error for now
                Err(SimpleVMError::Crypto)
            }
        },
    )
}

#[test]
fn group_with_admin() -> Result<(), Box<dyn std::error::Error>> {
    run_test_with_init(
        BYTECODES,
        InstantiateMsg {
            admin: Some(ADMIN.into()),
            members: vec![],
        },
        |vm| {
            if let ContractResult::<Binary>::Ok(binary) =
                cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(
                    vm,
                    r#"{ "total_weight": {} }"#.as_bytes(),
                )?
                .0
            {
                assert_eq!(binary, Binary(r#"{"weight":0}"#.as_bytes().to_vec()));
                Ok(())
            } else {
                // stand-in error for now
                Err(SimpleVMError::Crypto)
            }
        },
    )
}

#[test]
fn try_member_queries() -> Result<(), Box<dyn std::error::Error>> {
    run_test_with_init(
        BYTECODES,
        InstantiateMsg {
            admin: Some(ADMIN.into()),
            members: vec![
                Member {
                    addr: USER1.into(),
                    weight: 11,
                },
                Member {
                    addr: USER2.into(),
                    weight: 6,
                },
            ],
        },
        |vm| {
            let qmsg = QueryMsg::Member {
                addr: USER1.into(),
                at_height: None,
            };

            let msg = serde_json::to_string(&qmsg).map_err(|_| SimpleVMError::Crypto)?;

            if let ContractResult::<Binary>::Ok(binary) =
                cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(vm, msg.as_bytes())?.0
            {
                assert_eq!(binary, Binary(r#"{"weight":11}"#.as_bytes().to_vec()));
            } else {
                panic!("not ok")
            }

            // USER 2

            let qmsg = QueryMsg::Member {
                addr: USER2.into(),
                at_height: None,
            };

            let msg = serde_json::to_string(&qmsg).map_err(|_| SimpleVMError::Crypto)?;

            if let ContractResult::<Binary>::Ok(binary) =
                cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(vm, msg.as_bytes())?.0
            {
                assert_eq!(binary, Binary(r#"{"weight":6}"#.as_bytes().to_vec()));
            } else {
                panic!("not ok")
            }

            // USER 3 (nonexistant)

            let qmsg = QueryMsg::Member {
                addr: USER3.into(),
                at_height: None,
            };

            let msg = serde_json::to_string(&qmsg).map_err(|_| SimpleVMError::Crypto)?;

            if let ContractResult::<Binary>::Ok(binary) =
                cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(vm, msg.as_bytes())?.0
            {
                assert_eq!(binary, Binary(r#"{"weight":null}"#.as_bytes().to_vec()));
                Ok(())
            } else {
                Err(SimpleVMError::Crypto)
            }
        },
    )
}

#[test]
fn duplicate_members_instantiation() -> Result<(), Box<dyn std::error::Error>> {
    // This test tries to instantiate a contract with duplicate user entries.

    // it is a port of the following cw4-group test case
    // https://github.com/CosmWasm/cw-plus/blob/a959518fc04c47cb3db10e95117cc89a21868337/contracts/cw4-group/src/tests.rs#L69

    // However, it fails to error out in our case, for some reason, and the USER1 credentials get silently overwritten.

    let result = run_test_with_init(
        BYTECODES,
        InstantiateMsg {
            admin: Some(ADMIN.into()),
            members: vec![
                Member {
                    addr: USER1.into(),
                    weight: 5,
                },
                Member {
                    addr: USER2.into(),
                    weight: 6,
                },
                Member {
                    addr: USER1.into(),
                    weight: 6,
                },
            ],
        },
        |vm| {
            let qmsg = QueryMsg::Member {
                addr: USER1.into(),
                at_height: None,
            };

            let msg = serde_json::to_string(&qmsg).map_err(|_| SimpleVMError::Crypto)?;

            if let ContractResult::<Binary>::Ok(binary) =
                cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(vm, msg.as_bytes())?.0
            {
                assert_eq!(binary, Binary(r#"{"weight":null}"#.as_bytes().to_vec()));
                Ok(())
            } else {
                // stand-in error for now
                Err(SimpleVMError::Crypto)
            }
        },
    );

    assert!(result.is_err());
    Ok(())
}
