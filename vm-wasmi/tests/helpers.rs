use cosmwasm_std::{ContractResult, Empty};
use cosmwasm_vm::executor::{cosmwasm_call, InstantiateCall};
use cosmwasm_vm_wasmi::{
    create_simple_vm, instrument_contract, BankAccount, Gas, OwnedWasmiVM, SimpleWasmiVM,
    SimpleWasmiVMExtension,
};

use cw4_group::msg::InstantiateMsg;

pub trait InstantiateResultExt<T> {
    fn into_result(self) -> Result<T, String>;
}

impl<T> InstantiateResultExt<T> for ContractResult<T> {
    fn into_result(self) -> Result<T, String> {
        match self {
            ContractResult::Ok(t) => Ok(t),
            ContractResult::Err(e) => Err(e),
        }
    }
}

pub fn run_test_with_init<'a, F, R>(
    bytecodes: &[(&str, &[u8])],
    initmsg: InstantiateMsg,
    mut closure: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: PartialEq + core::fmt::Debug,
    F: for<'b> FnMut(&mut OwnedWasmiVM<SimpleWasmiVM<'b>>) -> R,
{
    let mut results = vec![];

    for (name, bytecode) in bytecodes {
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

        results.push((init, closure(&mut vm)))
    }

    // let results: Result<Vec<_>, _> = results.into_iter().collect();
    // let results = results?;

    let first = results.remove(0);

    // make sure all results are equal
    let _: Vec<_> = results.iter().map(|res| assert_eq!(&first, res)).collect();

    Ok(first.0 .0.into_result().map(|_| ())?)
}
