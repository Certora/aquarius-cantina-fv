// Helper function to read from storage and initialize ghost state

use soroban_sdk::Env;
use access_control::access::AccessControl;
use access_control::management::{SingleAddressManagementTrait, MultipleAddressesManagementTrait};
use access_control::role::Role;
use access_control::transfer::TransferOwnershipTrait;
use access_control::emergency::get_emergency_mode;
use upgrade::storage::{get_upgrade_deadline, get_future_wasm};
use ghost_state::GhostState;

pub fn initialize_ghost_state_from_storage(env: &Env) {
    let access_control: AccessControl = AccessControl::new(env);
    
    let admin = access_control.get_role_safe(&Role::Admin);
    let emergency_admin = access_control.get_role_safe(&Role::EmergencyAdmin);
    let rewards_admin = access_control.get_role_safe(&Role::RewardsAdmin);
    let operations_admin = access_control.get_role_safe(&Role::OperationsAdmin);
    let pause_admin = access_control.get_role_safe(&Role::PauseAdmin);
    let emergency_pause_admins = access_control.get_role_addresses(&Role::EmergencyPauseAdmin);
    
    let admin_transfer_deadline = access_control.get_transfer_ownership_deadline(&Role::Admin);
    let em_admin_transfer_deadline = access_control.get_transfer_ownership_deadline(&Role::EmergencyAdmin);
    
    let future_admin = if admin_transfer_deadline != 0 {
        Some(access_control.get_future_address(&Role::Admin))
    } else {
        None
    };
    
    let future_em_admin = if em_admin_transfer_deadline != 0 {
        Some(access_control.get_future_address(&Role::EmergencyAdmin))
    } else {
        None
    };
    
    let emergency_mode = get_emergency_mode(env);
    
    let upgrade_deadline = get_upgrade_deadline(env);
    let future_wasm = get_future_wasm(env);
    
    let state = GhostState {
        admin,
        emergency_admin,
        rewards_admin,
        operations_admin,
        pause_admin,
        emergency_pause_admins,
        admin_transfer_deadline,
        em_admin_transfer_deadline,
        future_admin,
        future_em_admin,
        emergency_mode,
        upgrade_deadline,
        future_wasm,
    };
    
    // Initialize the static GHOST_STATE
    GhostState::initialize(state);
}