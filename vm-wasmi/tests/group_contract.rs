#![feature(assert_matches)]
use serde::ser::Serialize;

use cosmwasm_std::{Binary, ContractResult, Empty};
use cosmwasm_vm::executor::QueryCall;
use cosmwasm_vm_wasmi::{
    create_simple_vm, instrument_contract, BankAccount, Gas, OwnedWasmiVM, SimpleWasmiVM,
    SimpleWasmiVMExtension,
};

use cosmwasm_vm::executor::{cosmwasm_call, InstantiateCall};

use cw4_group::msg::InstantiateMsg;

// use crate::state::{ADMIN, HOOKS};
// use crate::ContractError;

const INIT_ADMIN: &str = "a";
const USER1: &str = "b";
const USER2: &str = "c";
const USER3: &str = "d";

#[test]
fn empty_group() -> Result<(), Box<dyn std::error::Error>> {
    let bytecode = instrument_contract(include_bytes!("../../fixtures/cw4_group.wasm"));

    let address = BankAccount::new(0);
    let next = BankAccount::new(1);
    let funds = vec![];

    let mut extension = SimpleWasmiVMExtension::new(Gas::new(100_000_000), next);

    extension.add_contract(address, bytecode, None, String::from("cw4_group"));

    let mut vm = create_simple_vm(next, address, funds, &mut extension)?;

    let initmsg = InstantiateMsg {
        admin: None,
        members: vec![],
    };

    let msg = serde_json::to_string(&initmsg)?;

    let instantiated = cosmwasm_call::<InstantiateCall<Empty>, OwnedWasmiVM<SimpleWasmiVM>>(
        &mut vm,
        msg.as_bytes(),
    )?;

    // query total weight

    if let ContractResult::<Binary>::Ok(binary) =
        cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{ "total_weight": {} }"#.as_bytes(),
        )?
        .0
    {
        assert_eq!(binary, Binary(r#"{"weight":0}"#.as_bytes().to_vec()));
        Ok(())
    } else {
        panic!("not ok")
    }
}
