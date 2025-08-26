use access_control::emergency::get_emergency_mode;
use cvlr::{cvlr_satisfy, cvlr_assume};
use soroban_sdk::{Env, Address, BytesN};
use cvlr::asserts::cvlr_assert;
use cvlr_soroban_derive::rule;
use upgrade::storage::get_upgrade_deadline;

use crate::contract::FeesCollector;
use crate::interface::AdminInterface;
use access_control::interface::TransferableContract;
use upgrade::interface::UpgradeableContract;

// Role ID constants from access_control_harness.rs:
// 1 = Admin
// 2 = EmergencyAdmin
// 3 = RewardsAdmin
// 4 = OperationsAdmin
// 5 = PauseAdmin
// 6 = EmergencyPauseAdmin

//
// Ownership transfer
//

#[rule]
pub fn high_level_revert_ownership_transfer(e: Env, current_admin: Address, new_admin: Address) {

    cvlr_assume!(current_admin != new_admin);
    
    // Initialize and commit transfer
    FeesCollector::init_admin(e.clone(), current_admin.clone());
    FeesCollector::commit_transfer_ownership(e.clone(), current_admin.clone(), FeesCollector::role_id_to_symbol(e.clone(), 1), new_admin);
    
    // Revert before deadline
    FeesCollector::revert_transfer_ownership(e.clone(), current_admin.clone(), FeesCollector::role_id_to_symbol(e.clone(), 1));
    
    // Verify admin unchanged
    let final_admin = FeesCollector::h_get_admin_role(e);
    cvlr_assert!(final_admin == current_admin);
}

//
// Upgrade
//

#[rule]
pub fn high_level_upgrade_immediate_in_emergency(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
    FeesCollector::init_admin(e.clone(), admin.clone());
    FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash);
        
    FeesCollector::apply_upgrade(e.clone(), admin);
    
    // Immediate upgrade only in emergence mode
    cvlr_assert!(get_emergency_mode(&e));
}

#[rule]
pub fn high_level_upgrade_reachable(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
    FeesCollector::init_admin(e.clone(), admin.clone());
    FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash);
        
    FeesCollector::apply_upgrade(e.clone(), admin);
    
    // Immediate upgrade only in emergence mode
    cvlr_satisfy!(get_emergency_mode(&e));
}

#[rule]
pub fn high_level_revert_upgrade(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
    // Initialize and commit upgrade
    FeesCollector::init_admin(e.clone(), admin.clone());
    FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash);
    
    // Revert upgrade
    FeesCollector::revert_upgrade(e.clone(), admin);
    
    // Verify deadline was cleared
    cvlr_assert!(get_upgrade_deadline(&e) == 0);
}

#[rule]
pub fn high_level_revert_upgrade_reachable(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
    // Initialize and commit upgrade
    FeesCollector::init_admin(e.clone(), admin.clone());
    FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash);
    
    // Revert upgrade
    FeesCollector::revert_upgrade(e.clone(), admin);
    
    // Verify deadline was cleared
    cvlr_satisfy!(get_upgrade_deadline(&e) == 0);
}

//
// Emergency mode
//

#[rule]
pub fn high_level_emergency_mode_toggle(e: Env, admin: Address, emergency_admin: Address) {
    // Initialize roles
    FeesCollector::init_admin(e.clone(), admin.clone());
    FeesCollector::h_set_emergency_admin_address(e.clone(), emergency_admin.clone());
    
    // Initially emergency mode is off
    let initial_mode = FeesCollector::get_emergency_mode(e.clone());
    cvlr_assume!(!initial_mode);
    
    // Turn on emergency mode
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin.clone(), true);
    cvlr_assert!(FeesCollector::get_emergency_mode(e.clone()));
    
    // Turn off emergency mode
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin, false);
    cvlr_assert!(!FeesCollector::get_emergency_mode(e));
}

//
// Multi-step
//

#[rule]
pub fn high_level_concurrent_transfers_blocked(e: Env, admin: Address, new_admin1: Address, new_admin2: Address) {
    cvlr_assume!(admin != new_admin1);
    cvlr_assume!(admin != new_admin2);
    cvlr_assume!(new_admin1 != new_admin2);
    
    // Initialize admin
    FeesCollector::init_admin(e.clone(), admin.clone());
    
    // Commit first transfer
    FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), FeesCollector::role_id_to_symbol(e.clone(), 1), new_admin1);
    
    // Try to commit second transfer - should panic (mutual exclusion)
    FeesCollector::commit_transfer_ownership(e.clone(), admin, FeesCollector::role_id_to_symbol(e.clone(), 1), new_admin2);
    
    // Should never reach here
    cvlr_assert!(false);
}

#[rule]
pub fn high_level_deadline_expiry_prevents_apply(e: Env, admin: Address, new_admin: Address) {
    cvlr_assume!(admin != new_admin);
    
    // Initialize and commit transfer
    FeesCollector::init_admin(e.clone(), admin.clone());
    FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), FeesCollector::role_id_to_symbol(e.clone(), 1), new_admin);
    
    // Try to apply before deadline - should panic
    FeesCollector::apply_transfer_ownership(e.clone(), admin, FeesCollector::role_id_to_symbol(e.clone(), 1));
    
    // Should never reach here
    cvlr_assert!(false);
}
