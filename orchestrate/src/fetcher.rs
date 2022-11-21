use crate::error::Error;
use serde::{Deserialize, Serialize};

pub struct FileFetcher;

impl FileFetcher {
    pub fn from_url<S: AsRef<str>>(url: S) -> Result<Vec<u8>, Error> {
        Ok(reqwest::blocking::get(url.as_ref())
            .map_err(|_| Error::Network)?
            .bytes()
            .map_err(|_| Error::Network)?
            .to_vec())
    }
}

pub trait CosmosApi {
    const CONTRACT_ENDPOINT: &'static str;
    const CODE_ENDPOINT: &'static str;

    fn from_contract_addr<S: AsRef<str>>(
        endpoint: S,
        contract_address: S,
    ) -> Result<Vec<u8>, Error> {
        let response = reqwest::blocking::get(&format!(
            "{}/{}/{}",
            endpoint.as_ref(),
            Self::CONTRACT_ENDPOINT,
            contract_address.as_ref()
        ))
        .map_err(|_| Error::Network)?
        .text()
        .map_err(|_| Error::Network)?;

        let response: ContractResponse =
            serde_json::from_str(&response).map_err(|_| Error::CannotDeserialize)?;
        let code_id: u64 = response
            .contract_info
            .code_id
            .parse()
            .map_err(|_| Error::CannotDeserialize)?;
        Self::from_code_id(endpoint, code_id)
    }

    fn from_code_id<S: AsRef<str>>(endpoint: S, code_id: u64) -> Result<Vec<u8>, Error> {
        let response = reqwest::blocking::get(&format!(
            "{}/{}/{}",
            endpoint.as_ref(),
            Self::CODE_ENDPOINT,
            code_id
        ))
        .map_err(|_| Error::Network)?
        .text()
        .map_err(|_| Error::Network)?;

        let response: CosmosResponse =
            serde_json::from_str(&response).map_err(|_| Error::CannotDeserialize)?;
        base64::decode(&response.data).map_err(|_| Error::CannotDecode)
    }
}

pub struct CosmosFetcher;

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
