#![feature(assert_matches)]

#[cfg(test)]
mod tests {
    use cosmwasm_orchestrate::{
        fetcher::*,
        vm::{Account, StateBuilder},
        Api, Unit,
    };
    use cosmwasm_std::{
        to_binary, BankMsg, BlockInfo, Coin, ContractInfo, ContractResult, CosmosMsg, Env,
        MessageInfo, Timestamp,
    };
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
            .add_balance(sender.clone(), Coin::new(10_000_000, "denom"))
            .build();
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(100),
            chain_id: "asd".into(),
        };
        let info = MessageInfo {
            sender: sender.clone().into(),
            funds: vec![Coin::new(400_000, "denom")],
        };
        let (contract, _) = <Api>::instantiate_raw(
            &mut state,
            1,
            None,
            block.clone(),
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

        let env = Env {
            block: block.clone(),
            transaction: None,
            contract: ContractInfo {
                address: contract.clone().into(),
            },
        };

        let _ = <Api>::execute_raw(
            &mut state,
            env,
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
        let code = CosmosFetcher::from_contract_addr(
            "https://juno-api.polkachu.com",
            "juno19rqljkh95gh40s7qdx40ksx3zq5tm4qsmsrdz9smw668x9zdr3lqtg33mf",
        )
        .await
        .unwrap();
        let sender = Account::unchecked("sender");

        let mut state = StateBuilder::new().add_code(&code).build();
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(100),
            chain_id: "asd".into(),
        };
        let info = MessageInfo {
            sender: sender.clone().into(),
            funds: vec![],
        };
        let (contract, res) = <Api<Unit>>::instantiate(
            &mut state,
            1,
            None,
            block.clone(),
            None,
            info.clone(),
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
        let env = Env {
            block: block.clone(),
            transaction: None,
            contract: ContractInfo {
                address: contract.into(),
            },
        };
        assert_matches!(res, ContractResult::Ok(_));

        let _ = <Api>::execute(
            &mut state,
            env.clone(),
            info,
            100_000_000,
            ExecuteMsg::Transfer {
                recipient: "receiver".into(),
                amount: 10_000_u128.into(),
            },
        )
        .unwrap();

        assert_eq!(
            <Api<Unit>>::query_raw(
                &mut state,
                env,
                &serde_json::to_vec(&QueryMsg::Balance {
                    address: "receiver".into()
                })
                .unwrap()
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
