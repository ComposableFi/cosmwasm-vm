use crate::error::Error;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[allow(clippy::module_name_repetitions)]
pub struct FileFetcher;

impl FileFetcher {
    pub async fn from_url<S: AsRef<str>>(url: S) -> Result<Vec<u8>, Error> {
        Ok(reqwest::get(url.as_ref())
            .await
            .map_err(|_| Error::Network)?
            .bytes()
            .await
            .map_err(|_| Error::Network)?
            .to_vec())
    }
}

#[async_trait]
pub trait CosmosApi {
    const CONTRACT_ENDPOINT: &'static str;
    const CODE_ENDPOINT: &'static str;

    async fn from_contract_addr(endpoint: &str, contract_address: &str) -> Result<Vec<u8>, Error> {
        let response = reqwest::get(&format!(
            "{}/{}/{}",
            endpoint,
            Self::CONTRACT_ENDPOINT,
            contract_address
        ))
        .await
        .map_err(|_| Error::Network)?
        .text()
        .await
        .map_err(|_| Error::Network)?;

        let response: ContractResponse =
            serde_json::from_str(&response).map_err(|_| Error::CannotDeserialize)?;
        let code_id: u64 = response
            .contract_info
            .code_id
            .parse()
            .map_err(|_| Error::CannotDeserialize)?;
        Self::from_code_id(endpoint, code_id).await
    }

    async fn from_code_id(endpoint: &str, code_id: u64) -> Result<Vec<u8>, Error> {
        let response = reqwest::get(format!("{}/{}/{}", endpoint, Self::CODE_ENDPOINT, code_id))
            .await
            .map_err(|_| Error::Network)?
            .text()
            .await
            .map_err(|_| Error::Network)?;

        let response: CosmosResponse =
            serde_json::from_str(&response).map_err(|_| Error::CannotDeserialize)?;
        base64::decode(response.data).map_err(|_| Error::CannotDecode)
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct CosmosFetcher;

#[async_trait]
impl CosmosApi for CosmosFetcher {
    const CONTRACT_ENDPOINT: &'static str = "/cosmwasm/wasm/v1/contract";
    const CODE_ENDPOINT: &'static str = "/cosmwasm/wasm/v1/code";
}

#[derive(Debug, Serialize, Deserialize)]
struct CodeInfo {
    code_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ContractResponse {
    contract_info: CodeInfo,
}

#[derive(Debug, Serialize, Deserialize)]
struct CosmosResponse {
    data: String,
}
