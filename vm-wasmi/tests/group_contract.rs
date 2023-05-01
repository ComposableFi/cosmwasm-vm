#![feature(assert_matches)]

use cosmwasm_std::{Binary, ContractResult, Empty};
use cosmwasm_vm::executor::QueryCall;
use cosmwasm_vm_wasmi::{
    create_simple_vm, instrument_contract, BankAccount, Gas, OwnedWasmiVM, SimpleWasmiVM,
    SimpleWasmiVMExtension,
};

use cosmwasm_vm::executor::{cosmwasm_call, InstantiateCall};

use cw4::Member;
use cw4_group::msg::InstantiateMsg;
use cw4_group::msg::QueryMsg;

const ADMIN: &str = "0000";
const USER1: &str = "1000";
const USER2: &str = "2000";
const USER3: &str = "3000";

fn run_test_with_init<'a, F, R>(
    bytecodes: &[(&str, &[u8])],
    initmsg: InstantiateMsg,
    mut closure: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: PartialEq + core::fmt::Debug,
    F: for<'b> FnMut(&mut OwnedWasmiVM<SimpleWasmiVM<'b>>) -> Result<R, Box<dyn std::error::Error>>,
{
    let mut results = vec![];

    for (name, bytecode) in bytecodes {
        println!("testing {}", name);

        let address = BankAccount::new(0);
        let next = BankAccount::new(1);

        let mut extension = SimpleWasmiVMExtension::new(Gas::new(100_000_000), next);

        let funds = vec![];

        let instrumented = instrument_contract(bytecode);

        extension.add_contract(address, instrumented, None, String::from(*name));

        let next = extension.next_account_id().clone();

        let mut vm = create_simple_vm(next, address, funds, &mut extension)?;

        let msg = serde_json::to_string(&initmsg)?;

        let init = cosmwasm_call::<InstantiateCall<Empty>, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            msg.as_bytes(),
        )?;

        results.push(closure(&mut vm))
    }

    let results: Result<Vec<_>, _> = results.into_iter().collect();
    let results = results?;

    println!("all results {:?}", results);

    let first = &results[0];

    // make sure all results are equal
    let _: Vec<_> = results
        .iter()
        .skip(1)
        .map(|res| assert_eq!(first, res))
        .collect();

    Ok(())
}

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
                panic!("not ok")
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
                panic!("not ok")
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

            let msg = serde_json::to_string(&qmsg)?;

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

            let msg = serde_json::to_string(&qmsg)?;

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

            let msg = serde_json::to_string(&qmsg)?;

            if let ContractResult::<Binary>::Ok(binary) =
                cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(vm, msg.as_bytes())?.0
            {
                assert_eq!(binary, Binary(r#"{"weight":null}"#.as_bytes().to_vec()));
            } else {
                panic!("not ok")
            }

            Ok(())
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

            let msg = serde_json::to_string(&qmsg)?;

            if let ContractResult::<Binary>::Ok(binary) =
                cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(vm, msg.as_bytes())?.0
            {
                assert_eq!(binary, Binary(r#"{"weight":null}"#.as_bytes().to_vec()));
            } else {
                panic!("not ok")
            } //
            Ok(())
        },
    );

    assert!(result.is_err());
    Ok(())
}
