use soroban_sdk::{contractimpl, BytesN, Env};
use crate::contract::{FeesCollector, FeesCollectorArgs};
use crate::FeesCollectorClient;

#[contractimpl]
impl FeesCollector {
    pub fn h_get_upgrade_deadline(e: Env) -> u64 {
        upgrade::storage::get_upgrade_deadline(&e)
    }

    pub fn h_put_upgrade_deadline(e: Env, value: u64) {
        upgrade::storage::put_upgrade_deadline(&e, &value);
    }

    pub fn h_get_future_wasm(e: Env) -> Option<BytesN<32>> {
        upgrade::storage::get_future_wasm(&e)
    }

    pub fn h_put_future_wasm(e: Env, value: BytesN<32>) {
        upgrade::storage::put_future_wasm(&e, &value);
    }
}