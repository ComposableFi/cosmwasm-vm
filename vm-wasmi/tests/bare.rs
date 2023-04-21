#![feature(assert_matches)]
use core::assert_matches::assert_matches;

use cosmwasm_std::Empty;
use cosmwasm_vm_wasmi::{
    create_simple_vm, instrument_contract, BankAccount, Gas, OwnedWasmiVM, SimpleWasmiVM,
    SimpleWasmiVMExtension,
};

use cosmwasm_std::Binary;

use cosmwasm_vm::executor::{
    cosmwasm_call, CosmwasmExecutionResult, CosmwasmQueryResult, InstantiateCall,
    InstantiateResult, QueryCall, QueryResult,
};

#[test]
fn test_bare() {
    let bytecode = instrument_contract(include_bytes!("../../fixtures/cw20_base.wasm"));
    let sender = BankAccount::new(100);
    let address = BankAccount::new(10_000);
    let funds = vec![];

    let next_account_id = BankAccount::new(10_001);

    let mut extension = SimpleWasmiVMExtension::new(Gas::new(100_000_000), next_account_id);

    let code_id = 0x1337;

    extension.add_contract(address, code_id, bytecode, None, String::from("test"));

    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    assert_matches!(
        cosmwasm_call::<InstantiateCall<Empty>, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{
              "name": "Picasso",
              "symbol": "PICA",
              "decimals": 12,
              "initial_balances": [],
              "mint": null,
              "marketing": null
            }"#
            .as_bytes(),
        )
        .unwrap(),
        InstantiateResult(CosmwasmExecutionResult::Ok(_))
    );
    assert_eq!(
        cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{ "token_info": {} }"#.as_bytes(),
        )
        .unwrap(),
        QueryResult(CosmwasmQueryResult::Ok(Binary(
            r#"{"name":"Picasso","symbol":"PICA","decimals":12,"total_supply":"0"}"#
                .as_bytes()
                .to_vec()
        )))
    );
}
