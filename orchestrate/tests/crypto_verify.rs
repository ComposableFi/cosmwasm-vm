use cosmwasm_orchestrate::{
    vm::{Account, State, WasmAddressHandler},
    Direct, StateBuilder, WasmApi as Api,
};
use cosmwasm_std::{from_binary, Binary, BlockInfo, ContractInfo, Env, MessageInfo, Timestamp};
use serde::{Deserialize, Serialize};

const CREATOR: &str = "creator";

const SECP256K1_MESSAGE_HEX: &str = "5c868fedb8026979ebd26f1ba07c27eedf4ff6d10443505a96ecaf21ba8c4f0937b3cd23ffdc3dd429d4cd1905fb8dbcceeff1350020e18b58d2ba70887baa3a9b783ad30d3fbf210331cdd7df8d77defa398cdacdfc2e359c7ba4cae46bb74401deb417f8b912a1aa966aeeba9c39c7dd22479ae2b30719dca2f2206c5eb4b7";
const SECP256K1_SIGNATURE_HEX: &str = "207082eb2c3dfa0b454e0906051270ba4074ac93760ba9e7110cd9471475111151eb0dbbc9920e72146fb564f99d039802bf6ef2561446eb126ef364d21ee9c4";
const SECP256K1_PUBLIC_KEY_HEX: &str = "04051c1ee2190ecfb174bfe4f90763f2b4ff7517b70a2aec1876ebcfd644c4633fb03f3cfbd94b1f376e34592d9d41ccaf640bb751b00a1fadeb0c01157769eb73";

// TEST 3 test vector from https://tools.ietf.org/html/rfc8032#section-7.1
const ED25519_MESSAGE_HEX: &str = "af82";
const ED25519_SIGNATURE_HEX: &str = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
const ED25519_PUBLIC_KEY_HEX: &str =
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

// Signed text "connect all the things" using MyEtherWallet with private key b5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7
const ETHEREUM_MESSAGE: &str = "connect all the things";
const ETHEREUM_SIGNATURE_HEX: &str = "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";
const ETHEREUM_SIGNER_ADDRESS: &str = "0x12890D2cce102216644c59daE5baed380d84830c";

// TEST 2 test vector from https://tools.ietf.org/html/rfc8032#section-7.1
const ED25519_MESSAGE2_HEX: &str = "72";
const ED25519_SIGNATURE2_HEX: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
const ED25519_PUBLIC_KEY2_HEX: &str =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct VerifyResponse {
    verifies: bool,
}

fn get_env(contract_addr: &Account) -> Env {
    Env {
        block: BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(1000),
            chain_id: "hello".into(),
        },
        transaction: None,
        contract: ContractInfo {
            address: contract_addr.0.clone(),
        },
    }
}

fn message_info(sender: &Account) -> MessageInfo {
    MessageInfo {
        sender: sender.0.clone(),
        funds: vec![],
    }
}

fn setup() -> (Account, State<(), WasmAddressHandler>) {
    let wasm_code = include_bytes!("../../fixtures/crypto_verify.wasm");
    let code_id = 0;
    let mut state = StateBuilder::new()
        .add_code(code_id, wasm_code.as_slice())
        .build();

    let sender = Account::generate_from_seed::<WasmAddressHandler>(CREATOR).unwrap();

    let (addr, _) = <Api<Direct>>::instantiate_raw(
        &mut state,
        code_id,
        None,
        BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(1000),
            chain_id: "hello".into(),
        },
        None,
        message_info(&sender),
        100_000_000,
        r#"{}"#.as_bytes(),
    )
    .unwrap();

    (addr, state)
}

#[test]
fn cosmos_signature_verify_works() {
    let (addr, mut state) = setup();

    let message = hex::decode(SECP256K1_MESSAGE_HEX).unwrap();
    let signature = hex::decode(SECP256K1_SIGNATURE_HEX).unwrap();
    let public_key = hex::decode(SECP256K1_PUBLIC_KEY_HEX).unwrap();

    let verify_msg = format!(
        r#"
    {{
        "verify_cosmos_signature": {{
            "message": "{}",
            "signature": "{}",
            "public_key": "{}"
        }}
    }}
    "#,
        Binary(message),
        Binary(signature),
        Binary(public_key)
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: true });
}

#[test]
fn cosmos_signature_verify_fails() {
    let (addr, mut state) = setup();

    let mut message = hex::decode(SECP256K1_MESSAGE_HEX).unwrap();
    // alter hash
    message[0] ^= 0x01;
    let signature = hex::decode(SECP256K1_SIGNATURE_HEX).unwrap();
    let public_key = hex::decode(SECP256K1_PUBLIC_KEY_HEX).unwrap();

    let verify_msg = format!(
        r#"
    {{
        "verify_cosmos_signature": {{
            "message": "{}",
            "signature": "{}",
            "public_key": "{}"
        }}
    }}
    "#,
        Binary(message),
        Binary(signature),
        Binary(public_key)
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: false });
}

#[test]
fn ethereum_signature_verify_works() {
    let (addr, mut state) = setup();

    let message = ETHEREUM_MESSAGE;
    let signature = hex::decode(ETHEREUM_SIGNATURE_HEX).unwrap();
    let signer_address = ETHEREUM_SIGNER_ADDRESS;

    let verify_msg = format!(
        r#"
    {{
        "verify_ethereum_text": {{
            "message": "{}",
            "signature": "{}",
            "signer_address": "{}"
        }}
    }}
    "#,
        message,
        Binary(signature),
        signer_address,
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: true });
}

#[test]
fn ethereum_signature_verify_fails_for_corrupted_message() {
    let (addr, mut state) = setup();

    let message = format!("{ETHEREUM_MESSAGE}0");
    let signature = hex::decode(ETHEREUM_SIGNATURE_HEX).unwrap();
    let signer_address = ETHEREUM_SIGNER_ADDRESS;

    let verify_msg = format!(
        r#"
    {{
        "verify_ethereum_text": {{
            "message": "{}",
            "signature": "{}",
            "signer_address": "{}"
        }}
    }}
    "#,
        message,
        Binary(signature),
        signer_address,
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: false });
}

#[test]
fn ethereum_signature_verify_fails_for_corrupted_signature() {
    let (addr, mut state) = setup();

    let message = format!("{ETHEREUM_MESSAGE}0");
    let mut signature = hex::decode(ETHEREUM_SIGNATURE_HEX).unwrap();
    signature[5] ^= 0x1;
    let signer_address = ETHEREUM_SIGNER_ADDRESS;

    let verify_msg = format!(
        r#"
    {{
        "verify_ethereum_text": {{
            "message": "{}",
            "signature": "{}",
            "signer_address": "{}"
        }}
    }}
    "#,
        message,
        Binary(signature),
        signer_address,
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: false });
}

#[test]
fn verify_ethereum_transaction_works() {
    let (addr, mut state) = setup();

    // curl -sS -X POST --data '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0x3b87faa3410f33284124a6898fac1001673f0f7c3682d18f55bdff0031cce9ce"],"id":1}' -H "Content-type: application/json" https://rinkeby-light.eth.linkpool.io | jq .result
    // {
    //   "blockHash": "0x05ebd1bd99956537f49cfa1104682b3b3f9ff9249fa41a09931ce93368606c21",
    //   "blockNumber": "0x37ef3e",
    //   "from": "0x0a65766695a712af41b5cfecaad217b1a11cb22a",
    //   "gas": "0x226c8",
    //   "gasPrice": "0x3b9aca00",
    //   "hash": "0x3b87faa3410f33284124a6898fac1001673f0f7c3682d18f55bdff0031cce9ce",
    //   "input": "0x536561726368207478207465737420302e36353930383639313733393634333335",
    //   "nonce": "0xe1",
    //   "to": "0xe137f5264b6b528244e1643a2d570b37660b7f14",
    //   "transactionIndex": "0xb",
    //   "value": "0x53177c",
    //   "v": "0x2b",
    //   "r": "0xb9299dab50b3cddcaecd64b29bfbd5cd30fac1a1adea1b359a13c4e5171492a6",
    //   "s": "0x573059c66d894684488f92e7ce1f91b158ca57b0235485625b576a3b98c480ac"
    // }
    let nonce = 0xe1;
    let chain_id = 4; // Rinkeby, see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md#list-of-chain-ids
    let from = "0x0a65766695a712af41b5cfecaad217b1a11cb22a";
    let to = "0xe137f5264b6b528244e1643a2d570b37660b7f14";
    let gas_limit = 0x226c8;
    let gas_price = 0x3b9a_ca00;
    let value = 0x0053_177c;
    let data =
        hex::decode("536561726368207478207465737420302e36353930383639313733393634333335").unwrap();
    let r =
        hex::decode("b9299dab50b3cddcaecd64b29bfbd5cd30fac1a1adea1b359a13c4e5171492a6").unwrap();
    let s =
        hex::decode("573059c66d894684488f92e7ce1f91b158ca57b0235485625b576a3b98c480ac").unwrap();
    let v = 0x2b;

    let verify_msg = format!(
        r#"
    {{
        "verify_ethereum_transaction": {{
            "from": "{}",
            "to": "{}",
            "nonce": {},
            "gas_limit": "{}",
            "gas_price": "{}",
            "value": "{}",
            "data": "{}",
            "chain_id": {},
            "r": "{}",
            "s": "{}",
            "v": {}
        }}
    }}
        "#,
        from,
        to,
        nonce,
        gas_limit,
        gas_price,
        value,
        Binary(data),
        chain_id,
        Binary(r),
        Binary(s),
        v
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: true });
}

#[test]
fn tendermint_signature_verify_works() {
    let (addr, mut state) = setup();

    let message = hex::decode(ED25519_MESSAGE_HEX).unwrap();
    let signature = hex::decode(ED25519_SIGNATURE_HEX).unwrap();
    let public_key = hex::decode(ED25519_PUBLIC_KEY_HEX).unwrap();

    let verify_msg = format!(
        r#"
    {{
        "verify_tendermint_signature": {{
            "message": "{}",
            "signature": "{}",
            "public_key": "{}"
        }}
    }}
    "#,
        Binary(message),
        Binary(signature),
        Binary(public_key)
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: true });
}

#[test]
fn tendermint_signature_verify_fails() {
    let (addr, mut state) = setup();

    let mut message = hex::decode(ED25519_MESSAGE_HEX).unwrap();
    message[1] ^= 0x1;
    let signature = hex::decode(ED25519_SIGNATURE_HEX).unwrap();
    let public_key = hex::decode(ED25519_PUBLIC_KEY_HEX).unwrap();

    let verify_msg = format!(
        r#"
    {{
        "verify_tendermint_signature": {{
            "message": "{}",
            "signature": "{}",
            "public_key": "{}"
        }}
    }}
    "#,
        Binary(message),
        Binary(signature),
        Binary(public_key)
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: false });
}

#[test]
fn tendermint_signatures_batch_verify_works() {
    let (addr, mut state) = setup();

    let messages: Vec<_> = [ED25519_MESSAGE_HEX, ED25519_MESSAGE2_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();
    let signatures: Vec<_> = [ED25519_SIGNATURE_HEX, ED25519_SIGNATURE2_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();
    let public_keys: Vec<_> = [ED25519_PUBLIC_KEY_HEX, ED25519_PUBLIC_KEY2_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();

    let verify_msg = format!(
        r#"
    {{
        "verify_tendermint_batch": {{
            "messages": {messages:?},
            "signatures": {signatures:?},
            "public_keys": {public_keys:?}
        }}
    }}
    "#,
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: true });
}

#[test]
fn tendermint_signatures_batch_verify_message_multisig_works() {
    let (addr, mut state) = setup();

    // One message
    let messages: Vec<_> = [ED25519_MESSAGE_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();
    // Multiple signatures
    let signatures: Vec<_> = [ED25519_SIGNATURE_HEX, ED25519_SIGNATURE_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();
    // Multiple pubkeys
    let public_keys: Vec<_> = [ED25519_PUBLIC_KEY_HEX, ED25519_PUBLIC_KEY_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();

    let verify_msg = format!(
        r#"
    {{
        "verify_tendermint_batch": {{
            "messages": {messages:?},
            "signatures": {signatures:?},
            "public_keys": {public_keys:?}
        }}
    }}
    "#,
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: true });
}

#[test]
fn tendermint_signatures_batch_verify_single_public_key_works() {
    let (addr, mut state) = setup();

    // Multiple messages
    //FIXME: Use different messages / signatures
    let messages: Vec<_> = [ED25519_MESSAGE_HEX, ED25519_MESSAGE_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();
    // Multiple signatures
    let signatures: Vec<_> = [ED25519_SIGNATURE_HEX, ED25519_SIGNATURE_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();
    // One pubkey
    let public_keys: Vec<_> = [ED25519_PUBLIC_KEY_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();

    let verify_msg = format!(
        r#"
    {{
        "verify_tendermint_batch": {{
            "messages": {messages:?},
            "signatures": {signatures:?},
            "public_keys": {public_keys:?}
        }}
    }}
    "#,
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: true });
}

#[test]
fn tendermint_signatures_batch_verify_fails() {
    let (addr, mut state) = setup();

    let messages: Vec<_> = ["1234", ED25519_MESSAGE2_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();
    let signatures: Vec<_> = [ED25519_SIGNATURE_HEX, ED25519_SIGNATURE2_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();
    let public_keys: Vec<_> = [ED25519_PUBLIC_KEY_HEX, ED25519_PUBLIC_KEY2_HEX]
        .iter()
        .map(|m| format!("{}", Binary(hex::decode(m).unwrap())))
        .collect();

    let verify_msg = format!(
        r#"
    {{
        "verify_tendermint_batch": {{
            "messages": {messages:?},
            "signatures": {signatures:?},
            "public_keys": {public_keys:?}
        }}
    }}
    "#,
    );

    let res = <Api<Direct>>::query_raw(&mut state, get_env(&addr), verify_msg.as_bytes())
        .unwrap()
        .0
        .into_result()
        .unwrap();
    let res: VerifyResponse = from_binary(&res).unwrap();
    assert_eq!(res, VerifyResponse { verifies: false });
}
