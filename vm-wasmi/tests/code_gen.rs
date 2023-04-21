#![feature(assert_matches)]
use core::assert_matches::assert_matches;

use cosmwasm_std::{ContractResult, Empty, Response};
use cosmwasm_vm::executor::{
    cosmwasm_call, CosmwasmExecutionResult, ExecuteCall, ExecuteResult, InstantiateCall,
    InstantiateResult,
};

use cosmwasm_vm_wasmi::code_gen::{ModuleDefinition, WasmModule};
use cosmwasm_vm_wasmi::{
    create_simple_vm, BankAccount, Gas, OwnedWasmiVM, SimpleWasmiVM, SimpleWasmiVMExtension,
};

#[test]
fn basic() {
    let module: WasmModule = ModuleDefinition::new(vec![], 10, None).unwrap().into();
    let sender = BankAccount::new(100);
    let address = BankAccount::new(10_000);
    let funds = vec![];

    let mut extension =
        SimpleWasmiVMExtension::new(Gas::new(100_000_000), BankAccount::new(10_001));

    extension.add_contract(address, 0x1337, module.code, None, String::new());

    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    let result =
        cosmwasm_call::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(&mut vm, r#"{}"#.as_bytes())
            .unwrap();
    assert_matches!(result, InstantiateResult(CosmwasmExecutionResult::Ok(_)));
    let result =
        cosmwasm_call::<ExecuteCall, OwnedWasmiVM<SimpleWasmiVM>>(&mut vm, r#"{}"#.as_bytes())
            .unwrap();
    assert_matches!(result, ExecuteResult(CosmwasmExecutionResult::Ok(_)));
}

#[test]
fn instantiate_response() {
    let response = ContractResult::Ok(Response::<Empty>::new().add_attribute("Hello", "world!"));
    let response_2 = ContractResult::Ok(Response::<Empty>::new().add_attribute("Hello", "mars!"));
    let module: WasmModule = ModuleDefinition::with_instantiate_response(response.clone())
        .unwrap()
        .into();

    let sender = BankAccount::new(100);
    let address = BankAccount::new(10_000);
    let funds = vec![];

    let mut extension =
        SimpleWasmiVMExtension::new(Gas::new(100_000_000), BankAccount::new(10_001));

    extension.add_contract(address, 0x1337, module.code, None, String::new());

    let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
    let result =
        cosmwasm_call::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(&mut vm, r#"{}"#.as_bytes())
            .unwrap();
    assert_eq!(result, InstantiateResult(response));
    assert_ne!(result, InstantiateResult(response_2));
}
