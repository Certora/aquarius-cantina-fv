use crate::storage::DataKey;
use soroban_sdk::Env;
use utils::bump::bump_instance;

#[cfg(feature = "certora")]
use ghost_state::GhostState;

pub fn get_emergency_mode(e: &Env) -> bool {
    bump_instance(e);
    let value = e.storage()
        .instance()
        .get(&DataKey::EmergencyMode)
        .unwrap_or(false);
    
    #[cfg(feature = "certora")]
    {
        GhostState::update(|state| {
            state.emergency_mode = value;
        });
    }
    
    value
}

pub fn set_emergency_mode(e: &Env, value: &bool) {
    bump_instance(e);
    e.storage().instance().set(&DataKey::EmergencyMode, value);
    
    #[cfg(feature = "certora")]
    {
        GhostState::update(|state| {
            state.emergency_mode = *value;
        });
    }
}