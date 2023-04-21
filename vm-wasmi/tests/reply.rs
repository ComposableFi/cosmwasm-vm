use cosmwasm_std::Attribute;
use cosmwasm_vm::executor::{ExecuteCall, InstantiateCall};
use cosmwasm_vm::system::cosmwasm_system_entrypoint;
use cosmwasm_vm_wasmi::{
    create_simple_vm, instrument_contract, BankAccount, Gas, OwnedWasmiVM, SimpleWasmiVM,
    SimpleWasmiVMExtension,
};

#[test]
fn test_reply() {
    let code = instrument_contract(include_bytes!("../../fixtures/reflect.wasm"));
    let code_hackatom = instrument_contract(include_bytes!("../../fixtures/hackatom.wasm"));
    let sender = BankAccount::new(100);
    let address = BankAccount::new(10_000);
    let hackatom_address = BankAccount::new(10_001);
    let funds = vec![];

    let mut extension =
        SimpleWasmiVMExtension::new(Gas::new(100_000_000), BankAccount::new(10_002));

    extension.add_contract(address, 0x1337, code, None, String::new());
    extension.add_contract(hackatom_address, 0x1338, code_hackatom, None, String::new());

    {
        let mut vm =
            create_simple_vm(address, hackatom_address, funds.clone(), &mut extension).unwrap();
        let (_, events) = cosmwasm_system_entrypoint::<InstantiateCall, _>(
            &mut vm,
            r#"{"verifier": "10000", "beneficiary": "10000"}"#.as_bytes(),
        )
        .unwrap();

        assert!(events.iter().any(|e| e.attributes.contains(&Attribute {
            key: "Let the".into(),
            value: "hacking begin".into()
        })));
    }
    log::debug!("{:?}", extension.storage());
    {
        let mut vm = create_simple_vm(sender, address, funds, &mut extension).unwrap();
        let _ = cosmwasm_system_entrypoint::<InstantiateCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{}"#.as_bytes(),
        )
        .unwrap();

        let (_, events) = cosmwasm_system_entrypoint::<ExecuteCall, OwnedWasmiVM<SimpleWasmiVM>>(
            &mut vm,
            r#"{
                  "reflect_sub_msg": {
                    "msgs": [{
                      "id": 10,
                      "msg": {
                        "wasm": {
                          "execute": {
                            "contract_addr": "10001",
                            "msg": "eyAicmVsZWFzZSI6IHt9IH0=",
                            "funds": []
                          }
                        }
                      },
                      "gas_limit": null,
                      "reply_on": "always"
                    }]
                  }
                }"#
            .as_bytes(),
        )
        .unwrap();

        let attributes = vec![
            Attribute {
                key: "action".into(),
                value: "release".into(),
            },
            Attribute {
                key: "destination".into(),
                value: "10000".into(),
            },
            Attribute {
                key: "action".into(),
                value: "reflect_subcall".into(),
            },
        ];

        for attr in attributes {
            assert!(events.iter().any(|e| e.attributes.contains(&attr)));
        }
    }
}
