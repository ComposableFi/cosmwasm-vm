#![feature(assert_matches)]
use core::assert_matches::assert_matches;

extern crate alloc;

use alloc::collections::BTreeMap;
use cosmwasm_std::Empty;
use cosmwasm_vm_wasmi::{
    create_simple_vm, instrument_contract, BankAccount, Gas, OwnedWasmiVM, SimpleWasmiVM,
    SimpleWasmiVMExtension,
};

use cosmwasm_std::Binary;

use cosmwasm_vm::{
    executor::{
        cosmwasm_call, CosmwasmExecutionResult, CosmwasmQueryResult, InstantiateCall,
        InstantiateResult, QueryCall, QueryResult,
    },
    system::CosmwasmContractMeta,
};

#[test]
fn test_bare() {
    let code = instrument_contract(include_bytes!("../../fixtures/cw20_base.wasm"));
    let sender = BankAccount::new(100);
    let address = BankAccount::new(10_000);
    let funds = vec![];
    let mut extension = SimpleWasmiVMExtension {
        storage: BTreeMap::default(),
        codes: BTreeMap::from([(0x1337, code)]),
        contracts: BTreeMap::from([(
            address,
            CosmwasmContractMeta {
                code_id: 0x1337,
                admin: None,
                label: String::new(),
            },
        )]),
        next_account_id: BankAccount::new(10_001),
        transaction_depth: 0,
        gas: Gas::new(100_000_000),
        ..Default::default()
    };
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
