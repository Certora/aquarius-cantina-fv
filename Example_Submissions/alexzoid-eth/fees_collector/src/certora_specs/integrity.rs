use cvlr::{cvlr_satisfy, cvlr_assume};
use soroban_sdk::{Env, Address, BytesN, Symbol, Vec};
use cvlr::asserts::cvlr_assert;
use cvlr_soroban_derive::rule;
use access_control::constants::ADMIN_ACTIONS_DELAY;

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

#[rule]
pub fn integrity_emergency_mode(e: Env, emergency_admin: Address, value: u8) {
    
    // @note It seems there is an internal prover error when using bool in parameters natively
    //  https://prover.certora.com/output/52567/2eefc1e0560243cdb210dcb145f7d99d/?anonymousKey=418550b6f8be9074073cc1bb4d47ae317905a6cd
    // Convert u8 to bool: non-zero == true, zero == false
    let bool_value = value != 0;

    FeesCollector::set_emergency_mode(e.clone(), emergency_admin, bool_value);
    let result = FeesCollector::get_emergency_mode(e);
    cvlr_assert!(result == bool_value);
}

#[rule]
pub fn integrity_init_admin(e: Env, admin: Address) {
    FeesCollector::init_admin(e.clone(), admin.clone());
    let result = FeesCollector::h_get_admin_role(e);
    cvlr_assert!(result == admin);
}

#[rule]
pub fn integrity_future_address(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
    FeesCollector::commit_transfer_ownership(e.clone(), admin, role_name.clone(), new_address.clone());
    let result = FeesCollector::get_future_address(e, role_name);
    cvlr_assert!(result == new_address);
}

#[rule]
pub fn integrity_commit_transfer_deadline(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
    let deadline = e.ledger().timestamp() + ADMIN_ACTIONS_DELAY;
    FeesCollector::commit_transfer_ownership(e.clone(), admin, role_name.clone(), new_address.clone());
    let result = FeesCollector::h_get_transfer_ownership_dl(e, role_name);
    cvlr_assert!(result == deadline);
}

#[rule]
pub fn integrity_role_address_single(e: Env, role_name: Symbol, address: Address) {
    FeesCollector::h_set_role_address(e.clone(), role_name.clone(), address.clone());
    // Use h_get_role_safe since role_name could be any role, not just Admin
    let result = FeesCollector::h_get_role_safe(e, role_name);
    cvlr_assert!(result == Some(address));
}

#[rule]
pub fn integrity_role_addresses_multiple(e: Env, role_name: Symbol, addresses: Vec<Address>) {
    FeesCollector::h_set_role_addresses(e.clone(), role_name.clone(), addresses.clone());
    let result = FeesCollector::h_get_role_addresses(e, role_name);
    cvlr_assert!(result == addresses);
}

#[rule]
pub fn integrity_commit_upgrade_future_wasm(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
    FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash.clone());
    let future_wasm = FeesCollector::h_get_future_wasm(e);
    cvlr_assert!(future_wasm == Some(new_wasm_hash));
}

#[rule]
pub fn integrity_commit_upgrade_deadline(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
    let expected_deadline = e.ledger().timestamp() + ADMIN_ACTIONS_DELAY;
    FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash);
    let deadline = FeesCollector::h_get_upgrade_deadline(e);
    cvlr_assert!(deadline == expected_deadline);
}

#[rule]
pub fn integrity_upgrade_deadline_direct(e: Env, deadline: u64) {
    FeesCollector::h_put_upgrade_deadline(e.clone(), deadline);
    let result = FeesCollector::h_get_upgrade_deadline(e);
    cvlr_assert!(result == deadline);
}

#[rule]
pub fn integrity_future_wasm_direct(e: Env, wasm_hash: BytesN<32>) {
    FeesCollector::h_put_future_wasm(e.clone(), wasm_hash.clone());
    let result = FeesCollector::h_get_future_wasm(e);
    cvlr_assert!(result == Some(wasm_hash));
}

#[rule]
pub fn integrity_role_address_safe(e: Env, role_name: Symbol, address: Address) {
    FeesCollector::h_set_role_address(e.clone(), role_name.clone(), address.clone());
    let result = FeesCollector::h_get_role_safe(e, role_name);
    cvlr_assert!(result == Some(address));
}

#[rule]
pub fn integrity_init_all_roles(e: Env, admin: Address, emergency_admin: Address, 
                                    rewards_admin: Address, operations_admin: Address, 
                                    pause_admin: Address, emergency_pause_admins: Vec<Address>) {
    FeesCollector::h_init_all_roles(e.clone(), admin.clone(), emergency_admin.clone(), 
                                   rewards_admin.clone(), operations_admin.clone(), 
                                   pause_admin.clone(), emergency_pause_admins.clone());
    
    let admin_result = FeesCollector::h_get_admin_role(e.clone());
    let em_admin_result = FeesCollector::h_get_emergency_admin_safe(e.clone());
    let rewards_result = FeesCollector::h_get_rewards_admin_safe(e.clone());
    let ops_result = FeesCollector::h_get_operations_admin_safe(e.clone());
    let pause_result = FeesCollector::h_get_pause_admin_safe(e.clone());
    let em_pause_result = FeesCollector::h_get_role_addresses_by_id(e.clone(), 6);
    
    cvlr_assert!(admin_result == admin);
    cvlr_assert!(em_admin_result == Some(emergency_admin));
    cvlr_assert!(rewards_result == Some(rewards_admin));
    cvlr_assert!(ops_result == Some(operations_admin));
    cvlr_assert!(pause_result == Some(pause_admin));
    cvlr_assert!(em_pause_result == emergency_pause_admins);
}

#[rule]
pub fn integrity_privileged_addresses(e: Env, rewards_admin: Address, operations_admin: Address, 
                                         pause_admin: Address, emergency_pause_admins: Vec<Address>) {
    FeesCollector::h_set_privileged_addrs(e.clone(), rewards_admin.clone(), operations_admin.clone(), 
                                         pause_admin.clone(), emergency_pause_admins.clone());
    
    let rewards_result = FeesCollector::h_get_rewards_admin_safe(e.clone());
    let ops_result = FeesCollector::h_get_operations_admin_safe(e.clone());
    let pause_result = FeesCollector::h_get_pause_admin_safe(e.clone());
    let em_pause_result = FeesCollector::h_get_role_addresses_by_id(e.clone(), 6);
    
    cvlr_assert!(rewards_result == Some(rewards_admin));
    cvlr_assert!(ops_result == Some(operations_admin));
    cvlr_assert!(pause_result == Some(pause_admin));
    cvlr_assert!(em_pause_result == emergency_pause_admins);
}

#[rule]
pub fn integrity_address_has_role(e: Env, role_name: Symbol, address: Address) {
    FeesCollector::h_set_role_address(e.clone(), role_name.clone(), address.clone());
    let result = FeesCollector::h_address_has_role(e, address, role_name);
    cvlr_assert!(result == true);
}

#[rule]
pub fn integrity_assert_address_has_role(e: Env, role_name: Symbol, address: Address) {
    FeesCollector::h_set_role_address(e.clone(), role_name.clone(), address.clone());
    // Should not panic when address has the role
    FeesCollector::h_assert_address_has_role(e, address, role_name);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_assert_address_has_role_negative(e: Env, role_name: Symbol, address: Address, other_address: Address) {
    // Assume the address does NOT have the role (only other_address has it)
    cvlr_assume!(address != other_address);
    FeesCollector::h_set_role_address(e.clone(), role_name.clone(), other_address);
    // Should panic when address doesn't have the role
    FeesCollector::h_assert_address_has_role(e, address, role_name);
    // Should never reach this point
    cvlr_assert!(false);
}

#[rule]
pub fn integrity_get_key_admin(e: Env) {
    let result = FeesCollector::h_get_storage_key_by_id(e, 1); // ROLE_ID_ADMIN
    cvlr_assert!(result == 1); // DataKey::Admin
}

#[rule]
pub fn integrity_get_key_emergency_admin(e: Env) {
    let result = FeesCollector::h_get_storage_key_by_id(e, 2); // ROLE_ID_EMERGENCY_ADMIN
    cvlr_assert!(result == 2); // DataKey::EmergencyAdmin
}

#[rule]
pub fn integrity_get_key_rewards_admin(e: Env) {
    let result = FeesCollector::h_get_storage_key_by_id(e, 3); // ROLE_ID_REWARDS_ADMIN
    cvlr_assert!(result == 3); // DataKey::Operator (legacy name)
}

#[rule]
pub fn integrity_get_key_operations_admin(e: Env) {
    let result = FeesCollector::h_get_storage_key_by_id(e, 4); // ROLE_ID_OPERATIONS_ADMIN
    cvlr_assert!(result == 4); // DataKey::OperationsAdmin
}

#[rule] 
pub fn integrity_get_key_pause_admin(e: Env) {
    let result = FeesCollector::h_get_storage_key_by_id(e, 5); // ROLE_ID_PAUSE_ADMIN
    cvlr_assert!(result == 5); // DataKey::PauseAdmin
}

#[rule]
pub fn integrity_get_key_emergency_pause_admin(e: Env) {
    let result = FeesCollector::h_get_storage_key_by_id(e, 6); // ROLE_ID_EMERGENCY_PAUSE_ADMIN
    cvlr_assert!(result == 6); // DataKey::EmPauseAdmins
}

#[rule]
pub fn integrity_get_future_key_admin(e: Env) {
    let result = FeesCollector::h_get_future_storage_key_by_id(e, 1); // ROLE_ID_ADMIN
    cvlr_assert!(result == 7); // DataKey::FutureAdmin
}

#[rule]
pub fn integrity_get_future_key_emergency_admin(e: Env) {
    let result = FeesCollector::h_get_future_storage_key_by_id(e, 2); // ROLE_ID_EMERGENCY_ADMIN
    cvlr_assert!(result == 8); // DataKey::FutureEmergencyAdmin
}

#[rule]
pub fn integrity_get_future_deadline_key_admin(e: Env) {
    let result = FeesCollector::h_get_future_deadline_key_by_id(e, 1); // ROLE_ID_ADMIN
    cvlr_assert!(result == 9); // DataKey::TransferOwnershipDeadline
}

#[rule]
pub fn integrity_get_future_deadline_key_emergency_admin(e: Env) {
    let result = FeesCollector::h_get_future_deadline_key_by_id(e, 2); // ROLE_ID_EMERGENCY_ADMIN
    cvlr_assert!(result == 10); // DataKey::EmAdminTransferOwnershipDeadline
}

#[rule]
pub fn integrity_require_rewards_admin_with_rewards_admin(e: Env, rewards_admin: Address) {
    FeesCollector::h_set_rewards_admin_address(e.clone(), rewards_admin.clone());
    // Should not panic when address has rewards admin role
    FeesCollector::h_require_rewards_admin_or_owner(e, rewards_admin);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_require_rewards_admin_with_admin(e: Env, admin: Address) {
    // Initialize the admin role
    FeesCollector::init_admin(e.clone(), admin.clone());
    // Should not panic when address has admin role (owner)
    FeesCollector::h_require_rewards_admin_or_owner(e, admin);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_require_rewards_admin_negative(e: Env, address: Address, other_address: Address) {
    // Assume the address does NOT have admin or rewards admin role
    cvlr_assume!(address != other_address);
    FeesCollector::h_set_role_address_by_id(e.clone(), 1, other_address.clone());
    FeesCollector::h_set_role_address_by_id(e.clone(), 3, other_address);
    // Should panic when address doesn't have required roles
    FeesCollector::h_require_rewards_admin_or_owner(e, address);
    // Should never reach this point
    cvlr_assert!(false);
}

#[rule]
pub fn integrity_require_operations_admin_with_operations_admin(e: Env, operations_admin: Address) {
    FeesCollector::h_set_operations_admin_address(e.clone(), operations_admin.clone());
    // Should not panic when address has operations admin role
    FeesCollector::h_require_operations_admin_owner(e, operations_admin);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_require_operations_admin_with_admin(e: Env, admin: Address) {
    // Initialize the admin role
    FeesCollector::init_admin(e.clone(), admin.clone());
    // Should not panic when address has admin role (owner)
    FeesCollector::h_require_operations_admin_owner(e, admin);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_require_operations_admin_negative(e: Env, address: Address, other_address: Address) {
    // Assume the address does NOT have admin or operations admin role
    cvlr_assume!(address != other_address);
    FeesCollector::h_set_role_address_by_id(e.clone(), 1, other_address.clone());
    FeesCollector::h_set_role_address_by_id(e.clone(), 4, other_address);
    // Should panic when address doesn't have required roles
    FeesCollector::h_require_operations_admin_owner(e, address);
    // Should never reach this point
    cvlr_assert!(false);
}

#[rule]
pub fn integrity_require_pause_emergency_with_pause_admin(e: Env, pause_admin: Address) {
    FeesCollector::h_set_pause_admin_address(e.clone(), pause_admin.clone());
    // Should not panic when address has pause admin role
    FeesCollector::h_require_pause_emergency_admin(e, pause_admin);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_require_pause_emergency_with_emergency_pause_admin(e: Env, emergency_pause_admin: Address) {
    let emergency_pause_admins = Vec::from_array(&e, [emergency_pause_admin.clone()]);
    FeesCollector::h_set_role_addresses_by_id(e.clone(), 6, emergency_pause_admins);
    // Should not panic when address has emergency pause admin role
    FeesCollector::h_require_pause_emergency_admin(e, emergency_pause_admin);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_require_pause_emergency_with_admin(e: Env, admin: Address) {
    // Initialize the admin role
    FeesCollector::init_admin(e.clone(), admin.clone());
    // Should not panic when address has admin role (owner)
    FeesCollector::h_require_pause_emergency_admin(e, admin);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_require_pause_admin_with_pause_admin(e: Env, pause_admin: Address) {
    FeesCollector::h_set_pause_admin_address(e.clone(), pause_admin.clone());
    // Should not panic when address has pause admin role
    FeesCollector::h_require_pause_admin_or_owner(e, pause_admin);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_require_pause_admin_with_admin(e: Env, admin: Address) {
    // Initialize the admin role
    FeesCollector::init_admin(e.clone(), admin.clone());
    // Should not panic when address has admin role (owner)
    FeesCollector::h_require_pause_admin_or_owner(e, admin);
    cvlr_satisfy!(true);
}

#[rule]
pub fn integrity_require_pause_admin_negative(e: Env, address: Address, other_address: Address) {
    // Assume the address does NOT have admin or pause admin role
    cvlr_assume!(address != other_address);
    FeesCollector::h_set_role_address_by_id(e.clone(), 1, other_address.clone());
    FeesCollector::h_set_role_address_by_id(e.clone(), 5, other_address);
    // Should panic when address doesn't have required roles
    FeesCollector::h_require_pause_admin_or_owner(e, address);
    // Should never reach this point
    cvlr_assert!(false);
}