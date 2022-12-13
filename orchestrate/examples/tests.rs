#[cfg(test)]
mod tests {
    use cosmwasm_orchestrate::{
        fetcher::*,
        vm::{Account, JunoAddressHandler, WasmAddressHandler},
        *,
    };
    use cosmwasm_std::{BankMsg, Coin, CosmosMsg, MessageInfo};
    use cw20::{BalanceResponse, Cw20Coin};
    use cw20_base::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

    const REFLECT_URL: &'static str =
        "https://github.com/CosmWasm/cosmwasm/releases/download/v1.1.8/reflect.wasm";

    fn initialize() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            env_logger::init();
        });
    }

    #[tokio::test]
    async fn bank() {
        initialize();
        let code = FileFetcher::from_url(REFLECT_URL).await.unwrap();
        let sender = Account::generate_from_seed::<WasmAddressHandler>("sender").unwrap();
        let mut state = StateBuilder::<WasmAddressHandler>::new()
            .add_code(&code)
            .add_balance(sender.clone(), Coin::new(10_000_000, "denom"))
            .build();
        let mut info = MessageInfo {
            sender: sender.clone().into(),
            funds: vec![Coin::new(400_000, "denom")],
        };
        let (contract, _) = <WasmApi>::instantiate_raw(
            &mut state,
            1,
            None,
            block(),
            None,
            info.clone(),
            100_000_000,
            r#"{}"#.as_bytes(),
        )
        .unwrap();

        let msgs: Vec<CosmosMsg> = vec![
            BankMsg::Send {
                to_address: "receiver".into(),
                amount: vec![Coin::new(100_000, "denom")],
            }
            .into(),
            BankMsg::Burn {
                amount: vec![Coin::new(200_000, "denom")],
            }
            .into(),
        ];

        info.funds = vec![];
        let _ = <WasmApi>::execute_raw(
            &mut state,
            env(&contract),
            info.clone(),
            100_000_000,
            format!(
                r#"{{
                    "reflect_msg": {{
                        "msgs": {}
                    }}
                }}"#,
                serde_json::to_string(&msgs).unwrap()
            )
            .as_bytes(),
        );

        assert_eq!(state.db.bank.balance(&sender, "denom"), 9_600_000);
        assert_eq!(state.db.bank.balance(&contract, "denom"), 100_000);
        assert_eq!(
            state
                .db
                .bank
                .balance(&Account::unchecked("receiver"), "denom"),
            100_000
        );
        assert_eq!(*state.db.bank.supply.get("denom").unwrap(), 9_800_000);
    }

    #[tokio::test]
    async fn cw20() {
        initialize();

        // Fetch the wasm binary of the given contract from a remote chain.
        let code = CosmosFetcher::from_contract_addr(
            "https://juno-api.polkachu.com",
            "juno19rqljkh95gh40s7qdx40ksx3zq5tm4qsmsrdz9smw668x9zdr3lqtg33mf",
        )
        .await
        .unwrap();

        // Generate a Juno compatible address
        let sender = Account::generate_from_seed::<JunoAddressHandler>("sender").unwrap();

        // Create a VM state by providing the codes that will be executed.
        let mut state = StateBuilder::new().add_code(&code).build();

        let info = info(&sender);

        // Instantiate the cw20 contract
        let (contract, _) = <JunoApi>::instantiate(
            &mut state,
            1,
            None,
            block(),
            None,
            info.clone(),
            100_000_000,
            InstantiateMsg {
                name: "Picasso".into(),
                symbol: "PICA".into(),
                decimals: 12,
                initial_balances: vec![Cw20Coin {
                    amount: 10000000_u128.into(),
                    address: sender.into(),
                }],
                mint: None,
                marketing: None,
            },
        )
        .unwrap();

        // Transfer 10_000 PICA to the "receiver"
        let _ = <JunoApi>::execute(
            &mut state,
            env(&contract),
            info,
            100_000_000,
            ExecuteMsg::Transfer {
                recipient: Account::generate_from_seed::<JunoAddressHandler>("receiver")
                    .unwrap()
                    .into(),
                amount: 10_000_u128.into(),
            },
        )
        .unwrap();

        // Read the balance by using query. Note that the raw storage can be read here as well.
        let balance_response: BalanceResponse = JunoApi::<Direct>::query(
            &mut state,
            env(&contract),
            QueryMsg::Balance {
                address: Account::generate_from_seed::<JunoAddressHandler>("receiver")
                    .unwrap()
                    .into(),
            },
        )
        .unwrap();

        assert_eq!(Into::<u128>::into(balance_response.balance), 10_000_u128);
    }
}

fn main() {}
