#![feature(assert_matches)]

#[cfg(test)]
mod tests {
    use cosmwasm_std::to_binary;
    use cosmwasm_vm::executor::{
        CosmwasmExecutionResult, CosmwasmQueryResult, InstantiateResult, QueryResult,
    };
    use cw20::{BalanceResponse, Cw20Coin};
    use cw20_base::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
    use cw_orchestrate::{
        execute,
        fetcher::*,
        instantiate, query,
        vm::{Account, State},
    };
    use std::assert_matches::assert_matches;

    const CW20_BASE_URL: &'static str =
        "https://github.com/CosmWasm/cw-plus/releases/download/v0.16.0/cw20_base.wasm";

    #[tokio::test]
    async fn works() {
        let code = CosmosFetcher::from_contract_addr(
            "https://juno-api.polkachu.com",
            "juno19rqljkh95gh40s7qdx40ksx3zq5tm4qsmsrdz9smw668x9zdr3lqtg33mf",
        )
        .await
        .unwrap();
        let sender = Account::unchecked("sender");

        let mut state = State::with_codes(vec![&code]);
        let (contract, res) = instantiate(
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
        assert_matches!(res, InstantiateResult(CosmwasmExecutionResult::Ok(_)));

        let _ = execute(
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
            query(
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
