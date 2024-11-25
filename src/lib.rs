// Find all our documentation at https://docs.near.org
use hex::FromHex;
use near_sdk::json_types::U128;
use near_sdk::{env, near, require, serde_json, AccountId, Gas, Promise, PromiseError};
use omni_transaction::bitcoin::encoding::ToU64;
use omni_transaction::evm::evm_transaction::EVMTransaction;
use omni_transaction::evm::types::Signature;
use omni_transaction::transaction_builder::TransactionBuilder;
use omni_transaction::transaction_builder::TxBuilder;
use omni_transaction::types::EVM;
use sha2::{Digest, Sha256};
use signer::SignRequest;

pub mod signer;
use signer::*;

const SIGN_CALLBACK_GAS: Gas = Gas::from_tgas(50);

// Define the contract structure
#[near(contract_state)]
pub struct Contract {
    mpc_contract: AccountId,
    chain_id: u64,
    key_version: u64,
}

#[near(serializers = [json])]
pub struct TransactionInput {
    nonce: u64,
    receiver: String,
    max_priority_fee_per_gas: U128,
    max_fee_per_gas: U128,
    gas_limit: U128,
}

// Implement the contract structure
#[near]
impl Contract {
    #[init]
    #[private]
    pub fn new(mpc_contract: AccountId, chain_id: u64) -> Self {
        Self {
            mpc_contract,
            chain_id,
            key_version: 0,
        }
    }
    // Public method - returns the greeting saved, defaulting to DEFAULT_GREETING
    #[payable]
    pub fn proxy_mpc(&mut self, input: TransactionInput, path: String) -> Promise {
        // Convert the receiver address to a 20-byte array
        let address = convert_address(input.receiver);

        // Construct data for the transaction
        let data = vec![];

        // Construct the transaction
        let evm_tx = TransactionBuilder::new::<EVM>()
            .nonce(input.nonce)
            .to(address)
            .value(0)
            .input(data)
            .max_priority_fee_per_gas(input.max_priority_fee_per_gas.0)
            .max_fee_per_gas(input.max_fee_per_gas.0)
            .gas_limit(input.gas_limit.0)
            .chain_id(self.chain_id)
            .build();

        // Serialize the transaction to a JSON string
        let tx_json_string = serde_json::to_string(&evm_tx)
            .unwrap_or_else(|e| panic!("Failed to serialize transaction: {}", e));

        // Create the paylaod, hash it and convert to a 32-byte array
        let payload = evm_tx.build_for_signing();
        let hashed_payload = hash_payload(&payload);
        let mpc_payload: [u8; 32] = hashed_payload
            .try_into()
            .unwrap_or_else(|e| panic!("Failed to convert payload {:?}", e));

        let mpc_deposit = env::attached_deposit();
        let key_version = 0;

        // Call the MPC contract to sign the transaction
        ext_signer::ext(self.mpc_contract.clone())
            .with_attached_deposit(mpc_deposit)
            .sign(SignRequest::new(mpc_payload, path, key_version))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_CALLBACK_GAS)
                    .with_unused_gas_weight(0)
                    .mpc_callback(tx_json_string),
            )
    }

    // Public method - accepts a greeting, such as "howdy", and records it
    #[private]
    pub fn mpc_callback(
        &self,
        #[callback_result] result: Result<SignResult, PromiseError>,
        tx_json_string: String,
    ) -> Vec<u8> {
        if let Ok(sign_result) = result {
            // Get r and s from the sign result
            let big_r = &sign_result.big_r.affine_point;
            let s = &sign_result.s.scalar;
            let recovery_id = &sign_result.recovery_id;

            // Get r from big_r
            let r = &big_r[2..];

            // Convert hex to bytes
            let r_bytes = Vec::from_hex(r).expect("Invalid hex in r");
            let s_bytes = Vec::from_hex(s).expect("Invalid hex in s");

            // Add individual bytes together in the correct order
            let mut signature_bytes = [0u8; 65];
            signature_bytes[..32].copy_from_slice(&r_bytes);
            signature_bytes[32..64].copy_from_slice(&s_bytes);

            // Create signature
            let signature = Signature {
                v: recovery_id.to_u64(),
                r: r_bytes.to_vec(),
                s: s_bytes.to_vec(),
            };

            // Deserialize transaction
            let evm_tx = serde_json::from_str::<EVMTransaction>(&tx_json_string)
                .unwrap_or_else(|e| panic!("Failed to deserialize transaction: {:?}", e));

            // Add signature to transaction
            let evm_tx_signed = evm_tx.build_with_signature(&signature);

            // Return signed transaction
            evm_tx_signed
        } else {
            let error = result.unwrap_err();
            panic!("Callback failed with error {:?}", error);
        }
    }
}

pub fn convert_address(address: String) -> [u8; 20] {
    // Remove 0x prefix if it exists
    let address = address.trim_start_matches("0x");

    // Ensure the address has the correct length (40 hex characters, which is 20 bytes)
    require!(
        address.len() == 40,
        "Invalid Ethereum address length. Must be 40 hexadecimal characters."
    );

    // Decode the hex string into bytes
    let decoded = hex::decode(address).expect("Failed to decode the Ethereum address");

    // Convert the decoded bytes into a fixed-size array
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&decoded);
    bytes
}

pub fn hash_payload(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let result = hasher.finalize();
    result.into()
}
