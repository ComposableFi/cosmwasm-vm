use cosmwasm_std::{Attribute, Binary};
use cosmwasm_vm::executor::{
    cosmwasm_call, CosmwasmQueryResult, ExecuteCall, InstantiateCall, QueryCall, QueryResult,
};
use cosmwasm_vm::system::cosmwasm_system_entrypoint;
use cosmwasm_vm_wasmi::{
    create_simple_vm, instrument_contract, BankAccount, Gas, OwnedWasmiVM, SimpleWasmiVM,
    SimpleWasmiVMExtension,
};

#[test]
fn test_orchestration_base() {
    let code = instrument_contract(include_bytes!("../../fixtures/cw20_base.wasm"));
    let sender = BankAccount::new(100);
    let address = BankAccount::new(10_000);
    let funds = vec![];

    let mut extension =
        SimpleWasmiVMExtension::new(Gas::new(100_000_000), BankAccount::new(10_001));

    extension.add_contract(address, code, None, String::new());

    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    let _ = cosmwasm_system_entrypoint::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(
        &mut vm,
        format!(
            r#"{{
                  "name": "Picasso",
                  "symbol": "PICA",
                  "decimals": 12,
                  "initial_balances": [],
                  "mint": {{
                    "minter": "{}",
                    "cap": null
                  }},
                  "marketing": null
                }}"#,
            sender.id()
        )
        .as_bytes(),
    )
    .unwrap();

    let (_, events) = cosmwasm_system_entrypoint::<ExecuteCall, OwnedWasmiVM<SimpleWasmiVM>>(
        &mut vm,
        r#"{
              "mint": {
                "recipient": "10001",
                "amount": "5555"
              }
            }"#
        .as_bytes(),
    )
    .unwrap();
    let attributes = vec![
        Attribute {
            key: "action".into(),
            value: "mint".into(),
        },
        Attribute {
            key: "to".into(),
            value: "10001".into(),
        },
        Attribute {
            key: "amount".into(),
            value: "5555".into(),
        },
    ];

    for attr in attributes {
        assert!(events.iter().any(|e| e.attributes.contains(&attr)));
    }
}

#[test]
fn test_orchestration_advanced() {
    let code = instrument_contract(include_bytes!("../../fixtures/hackatom.wasm"));
    let sender = BankAccount::new(100);
    let address = BankAccount::new(10_000);
    let funds = vec![];

    let mut extension =
        SimpleWasmiVMExtension::new(Gas::new(100_000_000), BankAccount::new(10_001));

    extension.add_contract(address, code, None, String::new());

    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    assert_eq!(
        cosmwasm_call::<QueryCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{ "recurse": { "depth": 10, "work": 10 }}"#.as_bytes()
        )
        .unwrap(),
        QueryResult(CosmwasmQueryResult::Ok(Binary(
            r#"{"hashed":"K4xL+Gub1930CJU6hdpwf0t3KNk27f5efqy9+YA6iio="}"#
                .as_bytes()
                .to_vec()
        )))
    );
}
