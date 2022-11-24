#![feature(assert_matches)]

#[cfg(test)]
mod tests {
    use cosmwasm_orchestrate::{
        fetcher::*,
        vm::{Account, StateBuilder},
        Entrypoint, Full, Unit,
    };
    use cosmwasm_std::{to_binary, BankMsg, Coin, ContractResult, CosmosMsg};
    use cosmwasm_vm::executor::{CosmwasmQueryResult, QueryResult};
    use cw20::{BalanceResponse, Cw20Coin};
    use cw20_base::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
    use std::assert_matches::assert_matches;

    const REFLECT_URL: &'static str =
        "https://github.com/CosmWasm/cosmwasm/releases/download/v1.1.8/reflect.wasm";

    #[tokio::test]
    async fn bank() {
        let code = FileFetcher::from_url(REFLECT_URL).await.unwrap();
        let sender = Account::unchecked("sender");
        let mut state = StateBuilder::new()
            .add_code(&code)
            .add_balance(&sender, &Coin::new(10_000_000, "denom"))
            .build();
        let (contract, _) = Full::instantiate_raw(
            &mut state,
            &sender,
            1,
            None,
            vec![Coin::new(400_000, "denom")],
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

        let _ = Full::execute_raw(
            &mut state,
            &sender,
            &contract,
            vec![],
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
        let code = CosmosFetcher::from_contract_addr(
            "https://juno-api.polkachu.com",
            "juno19rqljkh95gh40s7qdx40ksx3zq5tm4qsmsrdz9smw668x9zdr3lqtg33mf",
        )
        .await
        .unwrap();
        let sender = Account::unchecked("sender");

        let mut state = StateBuilder::new().add_code(&code).build();
        let (contract, res) = Unit::instantiate(
            &mut state,
            &sender,
            1,
            None,
            vec![],
            100_000_000,
            InstantiateMsg {
                name: "Picasso".into(),
                symbol: "PICA".into(),
                decimals: 12,
                initial_balances: vec![Cw20Coin {
                    amount: 10000000_u128.into(),
                    address: sender.0.clone().into_string(),
                }],
                mint: None,
                marketing: None,
            },
        )
        .unwrap();
        assert_matches!(res, ContractResult::Ok(_));

        let _ = Full::execute(
            &mut state,
            &sender,
            &contract,
            vec![],
            100_000_000,
            ExecuteMsg::Transfer {
                recipient: "receiver".into(),
                amount: 10_000_u128.into(),
            },
        )
        .unwrap();

        assert_eq!(
            Unit::query(
                &mut state,
                &contract,
                QueryMsg::Balance {
                    address: "receiver".into()
                }
            )
            .unwrap(),
            QueryResult(CosmwasmQueryResult::Ok(
                to_binary(&BalanceResponse {
                    balance: 10_000_u128.into()
                })
                .unwrap()
            ))
        );
    }
}

fn main() {}
