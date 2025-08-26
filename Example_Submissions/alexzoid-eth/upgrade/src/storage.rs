use soroban_sdk::{contracttype, BytesN, Env};
use utils::bump::bump_instance;

#[cfg(feature = "certora")]
use ghost_state::GhostState;

#[derive(Clone)]
#[contracttype]
enum DataKey {
    UpgradeDeadline,
    FutureWASM,
}

// upgrade deadline
pub fn get_upgrade_deadline(e: &Env) -> u64 {
    bump_instance(e);
    let value = e.storage()
        .instance()
        .get(&DataKey::UpgradeDeadline)
        .unwrap_or(0);

    #[cfg(feature = "certora")]
    {
        GhostState::update(|state| {
            state.upgrade_deadline = value;
        });
    }

    value
}

pub fn put_upgrade_deadline(e: &Env, value: &u64) {
    bump_instance(e);
    e.storage().instance().set(&DataKey::UpgradeDeadline, value);

    #[cfg(feature = "certora")]
    {
        GhostState::update(|state| {
            state.upgrade_deadline = *value;
        });
    }
}

pub fn get_future_wasm(e: &Env) -> Option<BytesN<32>> {
    bump_instance(e);
    let value = e.storage().instance().get(&DataKey::FutureWASM);

    #[cfg(feature = "certora")]
    {
        let value_clone = value.clone();
        GhostState::update(|state| {
            state.future_wasm = value_clone;
        });
    }

    value
}

pub fn put_future_wasm(e: &Env, value: &BytesN<32>) {
    bump_instance(e);
    e.storage().instance().set(&DataKey::FutureWASM, value);

    #[cfg(feature = "certora")]
    {
        let value_clone = value.clone();
        GhostState::update(|state| {
            state.future_wasm = Some(value_clone);
        });
    }
}
