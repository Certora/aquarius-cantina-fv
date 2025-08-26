use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::{clog};
use cvlr_soroban::{nondet_address};
use cvlr_soroban_derive::rule;

use crate::certora_specs::util::{get_role_address, is_role, get_deadline, get_key, get_future_address};
use upgrade::storage::{DataKey as UpgradeDataKey, get_future_wasm, get_upgrade_deadline};
pub use crate::contract::FeesCollector;
use access_control::role::{Role, SymbolRepresentation};
use access_control::interface::TransferableContract;
use access_control::transfer::TransferOwnershipTrait;
use access_control::access::{AccessControl, AccessControlTrait};
use access_control::storage::{StorageTrait, DataKey};
use access_control::management::{SingleAddressManagementTrait, MultipleAddressesManagementTrait};
use access_control::utils::{
    require_pause_admin_or_owner, require_pause_or_emergency_pause_admin_or_owner,
    require_rewards_admin_or_owner, require_operations_admin_or_owner
};
use crate::interface::AdminInterface;
use upgrade::interface::UpgradeableContract;
use upgrade::constants::UPGRADE_DELAY;
use access_control::constants::ADMIN_ACTIONS_DELAY;

/**
 * These are some example rules to help get started.
*/

#[rule]
pub fn init_admin_sets_admin(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    FeesCollector::init_admin(e, address.clone());
    let addr = get_role_address();
    // syntax of how to use `clog!`. This is helpful for calltrace when a rule fails.
    clog!(cvlr_soroban::Addr(&addr));
    cvlr_assert!(addr == address);
}

#[rule]
pub fn only_emergency_admin_sets_emergency_mode(e: Env) {
    let address = nondet_address();
    let value: bool = cvlr::nondet();
    cvlr_assume!(!is_role(&address, &Role::EmergencyAdmin));
    FeesCollector::set_emergency_mode(e, address, value);
    cvlr_assert!(false); // should not reach and therefore should pass
}

#[rule]
pub fn set_emergency_mode_success(e: Env) {
    let value: bool = cvlr::nondet();
    access_control::emergency::set_emergency_mode(&e, &value);
    cvlr_assert!(access_control::emergency::get_emergency_mode(&e) == value);
}

//*************************** */
//* RULES FOR PRIVATE MUTANTS */
//*************************** */

// init_admin should fail if admin already set
#[rule]
pub fn init_admin_already_set_fails(e: Env) {
    let address = nondet_address();
    let _ = get_role_address();
    FeesCollector::init_admin(e, address);
    cvlr_assert!(false);
}

// version returns correct version (150)
#[rule]
pub fn version_correct() {
    let v = FeesCollector::version();
    cvlr_assert!(v == 150);
}

// commit_upgrade RULES
// 1. CORRECTNESS RULES

// commit_upgrade correctly updates upgrade deadline and future wasm
#[rule]
fn commit_upgrade_correct(e: Env, wasm_hash: BytesN<32>) {
    let admin = nondet_address();
    let timestamp = e.ledger().timestamp();
    FeesCollector::commit_upgrade(e.clone(), admin, wasm_hash.clone());
    let deadline_after = get_upgrade_deadline(&e);
    cvlr_assert!(deadline_after == timestamp + UPGRADE_DELAY);
    cvlr_assert!(e.storage().instance()
        .get(&UpgradeDataKey::FutureWASM) == Some (wasm_hash));
}

// 2. ASSERTION CHECKS

// RULE FOR PUBLIC MUTANT 0
// commit_upgrade should fail if the caller is not admin
#[rule]
fn commit_upgrade_requires_admin(e: Env, wasm_hash: BytesN<32>) {
    let address = nondet_address();
    cvlr_assume!(!is_role(&address, &Role::Admin));
    FeesCollector::commit_upgrade(e, address, wasm_hash);
    cvlr_assert!(false);
}

// commit_upgrade should fail if upgrade deadline is not zero
#[rule]
fn commit_upgrade_another_action_active_fails(e: Env, wasm_hash: BytesN<32>) {
    let admin = nondet_address();
    cvlr_assume!(get_upgrade_deadline(&e) != 0);
    FeesCollector::commit_upgrade(e, admin, wasm_hash);
    cvlr_assert!(false);
}

// apply_upgrade RULES
// 1. CORRECTNESS RULES

// apply_upgrade sets upgrade deadline to 0 and applies committed wasm
#[rule]
fn apply_upgrade_correct(e: Env) {
    let admin = nondet_address();
    let expected_wasm = get_future_wasm(&e);
    cvlr_assume!(expected_wasm.is_some());
    let new_wasm = FeesCollector::apply_upgrade(e.clone(), admin);
    cvlr_assert!(expected_wasm == Some (new_wasm));
    cvlr_assert!(e.storage().instance()
        .get::<upgrade::storage::DataKey, u64>(&UpgradeDataKey::UpgradeDeadline)
        .unwrap() == 0);
}

// 2. ASSERTION CHECKS

// apply_upgrade should fail if the caller is not admin
#[rule]
fn apply_upgrade_requires_admin(e: Env) {
    let address = nondet_address();
    cvlr_assume!(!is_role(&address, &Role::Admin));
    FeesCollector::apply_upgrade(e, address);
    cvlr_assert!(false);
}

// apply_upgrade should fail if deadline has not reached (except emergency)
#[rule]
fn apply_upgrade_before_deadline_fails(e: Env) {
    let admin = nondet_address();
    cvlr_assume!(!access_control::emergency::get_emergency_mode(&e) &&
        e.ledger().timestamp() < get_upgrade_deadline(&e));
    FeesCollector::apply_upgrade(e, admin);
    cvlr_assert!(false);
}

// apply_upgrade should fail if deadline is not set (except emergency)
#[rule]
fn apply_upgrade_no_action_active_fails(e: Env) {
    let admin = nondet_address();
    cvlr_assume!(!access_control::emergency::get_emergency_mode(&e)
        && get_upgrade_deadline(&e) == 0);
    FeesCollector::apply_upgrade(e, admin);
    cvlr_assert!(false);
}

// apply_upgrade should fail if there is no committed wasm
#[rule]
fn apply_upgrade_not_initialized_fails(e: Env) {
    let admin = nondet_address();
    let expected_wasm = get_future_wasm(&e);
    cvlr_assume!(!expected_wasm.is_some());
    FeesCollector::apply_upgrade(e, admin);
    cvlr_assert!(false);
}

// revert_upgrade RULES
// 1. CORRECTNESS RULES

// revert_upgrade sets upgrade_deadline to 0
#[rule]
fn revert_upgrade_correct(e: Env) {
    let admin = nondet_address();
    FeesCollector::revert_upgrade(e.clone(), admin);
    cvlr_assert!(e.storage().instance()
        .get::<upgrade::storage::DataKey, u64>(&UpgradeDataKey::UpgradeDeadline)
        .unwrap() == 0);
}

// 2. ASSERTION CHECKS

// revert_upgrade fail if the caller is not admin
#[rule]
fn revert_upgrade_requires_admin(e: Env) {
    let address = nondet_address();
    cvlr_assume!(!is_role(&address, &Role::Admin));
    FeesCollector::revert_upgrade(e, address);
    cvlr_assert!(false);
}

// set(get)_emergency_mode RULES
// also cover access_control::emergency
// 1. CORRECTNESS RULES

// set_emergency_mode correctly updates emergency mode
#[rule]
fn set_emergency_mode_correct(e: Env) {
    let emergency_admin = nondet_address();
    let value: bool = cvlr::nondet();
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin, value);
    cvlr_assert!(e.storage().instance().get(&DataKey::EmergencyMode) == Some (value));
}

// RULE FOR PUBLIC MUTANT 2
// get_emergency_mode should return actual emergency mode
#[rule]
fn get_emergency_mode_correct(e: Env) {
    let emergency_admin = nondet_address();
    let value: bool = cvlr::nondet();
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin, value);
    let emergency = FeesCollector::get_emergency_mode(e.clone());
    cvlr_assert!(e.storage().instance().get(&DataKey::EmergencyMode) == Some (emergency));
    cvlr_assert!(emergency == value);
}

// commit_transfer_ownership RULES
// also cover access_control::transfer
// 1. CORRECTNESS RULES

// commit_transfer_ownership correctly sets new deadline and future_address for role upgrade
#[rule]
pub fn commit_transfer_ownership_correct(e: Env, role_name: &Symbol) {
    let admin = nondet_address();
    let new_admin = nondet_address();
    let role= Role::from_symbol(&e, role_name.clone());
    let timestamp = e.ledger().timestamp();
    FeesCollector::commit_transfer_ownership(e.clone(), admin, role_name.clone(), new_admin.clone());
    let deadline_after = get_deadline(&role);
    cvlr_assert!(deadline_after == timestamp + ADMIN_ACTIONS_DELAY);
    cvlr_assert!(new_admin == get_future_address(&role));
}

// 2. ASSERTION CHECKS

// commit_transfer_ownership should fail if the caller is not admin
#[rule]
pub fn commit_transfer_ownership_requires_admin(e: Env, role_name: Symbol) {
    let address  = nondet_address();
    cvlr_assume!(!is_role(&address, &Role::Admin));
    let new_admin = nondet_address();
    FeesCollector::commit_transfer_ownership(e, address, role_name, new_admin);
    cvlr_assert!(false);
}

// commit_transfer_ownership should fail if the committed role is not Admin or EmergencyAdmin
#[rule]
pub fn commit_transfer_ownership_bad_role_usage_fails(e: Env, role_name: Symbol) {
    let admin = nondet_address();
    let new_admin = nondet_address();
    cvlr_assume!(role_name != Symbol::new(&e, "Admin") && role_name != Symbol::new(&e, "EmergencyAdmin"));
    FeesCollector::commit_transfer_ownership(e, admin, role_name, new_admin);
    cvlr_assert!(false);
}

// commit_transfer_ownership should fail if the deadline is not 0
#[rule]
pub fn commit_transfer_ownership_another_action_active_fails(e: Env, role_name: &Symbol) {
    let admin = nondet_address();
    let new_admin = nondet_address();
    let role= Role::from_symbol(&e, role_name.clone());
    cvlr_assume!(get_deadline(&role) != 0);
    FeesCollector::commit_transfer_ownership(e, admin, role_name.clone(), new_admin);
    cvlr_assert!(false);
}

// apply_transfer_ownership RULES
// 1. CORRECTNESS RULES

// apply_transfer_ownership correctly sets new deadline and future_address for role upgrade
#[rule]
pub fn apply_transfer_ownership_correct(e: Env, role_name: &Symbol) {
    let admin = nondet_address();
    let role= Role::from_symbol(&e, role_name.clone());
    let new_admin = get_future_address(&role);
    FeesCollector::apply_transfer_ownership(e.clone(), admin, role_name.clone());
    cvlr_assert!(get_deadline(&role) == 0);
    cvlr_assert!(is_role(&new_admin, &role));
}

// apply_transfer_ownership correctly returns new address
#[rule]
pub fn apply_transfer_ownership_return_correct(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    let expected = get_future_address(role);
    let future_address = ac.apply_transfer_ownership(role);
    cvlr_assert!(future_address == expected);
}

// 2. ASSERTION_CHECKS

// apply_transfer_ownership should fail if the caller is not admin
// RULE FOR PUBLIC MUTANT 1
#[rule]
pub fn apply_transfer_ownership_requires_admin(e: Env, role_name: Symbol) {
    let address = nondet_address();
    cvlr_assume!(!is_role(&address, &Role::Admin));
    FeesCollector::apply_transfer_ownership(e, address, role_name);
    cvlr_assert!(false);
}

// apply_transfer_ownership should fail if deadline has not reached
// and the role already has an owner
#[rule]
fn apply_transfer_ownership_before_deadline_fails(e: Env, role_name: Symbol) {
    let admin = nondet_address();
    let role= Role::from_symbol(&e, role_name.clone());
    let role_key = get_key(&role);
    let has_value = e.storage().instance().has(&role_key);
    cvlr_assume!(has_value && e.ledger().timestamp() < get_deadline(&role));
    FeesCollector::apply_transfer_ownership(e, admin, role_name);
    cvlr_assert!(false);
}

// apply_transfer_ownership should fail if deadline has not reached
#[rule]
fn apply_transfer_ownership_no_action_active_fails(e: Env, role_name: Symbol) {
    let admin = nondet_address();
    let role= Role::from_symbol(&e, role_name.clone());
    cvlr_assume!(get_deadline(&role) == 0);
    FeesCollector::apply_transfer_ownership(e, admin, role_name);
    cvlr_assert!(false);
}

// apply_transfer_ownership should fail if there is no committed address
#[rule]
fn apply_transfer_ownership_no_future_address_fails(e: Env, role_name: Symbol) {
    let admin = nondet_address();
    let role= Role::from_symbol(&e, role_name.clone());
    // clog!(cvlr_soroban::Addr(&get_role_address()));
    let ac = AccessControl::new(&e);
    cvlr_assume!(!e.storage().instance()
        .get::<access_control::storage::DataKey, Address>(&ac.get_future_key(&role))
        .is_some());
    FeesCollector::apply_transfer_ownership(e, admin, role_name);
    cvlr_assert!(false);
}

// revert_transfer_ownership RULES
// 1. CORRECTNESS RULES

// revert_transfer_ownership correctly sets deadline to zero
#[rule]
pub fn revert_transfer_ownership_correct(e: Env, role_name: &Symbol) {
    let admin = nondet_address();
    let role= Role::from_symbol(&e, role_name.clone());
    FeesCollector::revert_transfer_ownership(e.clone(), admin, role_name.clone());
    cvlr_assert!(get_deadline(&role) == 0);
}

// 2. ASSERTION_CHECKS

// revert_transfer_ownership should fail if the caller is not admin
#[rule]
pub fn revert_transfer_ownership_requires_admin(e: Env, role_name: Symbol) {
    let address = nondet_address();
    cvlr_assume!(!is_role(&address, &Role::Admin));
    FeesCollector::revert_transfer_ownership(e, address, role_name);
    cvlr_assert!(false);
}

// get_future_address RULES
// 1. CORRECTNESS RULES

// get_future_address correctly returns the future address for the role
#[rule]
pub fn get_future_address_correct(e: Env, role_name: Symbol) {
    let role= Role::from_symbol(&e, role_name.clone());
    let ac = AccessControl::new(&e);
    cvlr_assume!(get_deadline(&role) != 0);
    let addr = FeesCollector::get_future_address(e.clone(), role_name.clone());
    cvlr_assert!(Some (addr) == e.storage().instance().get(&ac.get_future_key(&role)));
}

// get_future_address returns current address if the transfer is not committed
#[rule]
pub fn get_future_address_no_commit(e: Env, role_name: Symbol) {
    let role= Role::from_symbol(&e, role_name.clone());
    let addr_default = nondet_address();
    cvlr_assume!(get_deadline(&role) == 0 && is_role(&addr_default, &role));
    let addr = FeesCollector::get_future_address(e.clone(), role_name.clone());
    cvlr_assert!(addr_default == addr);
}

// 2. ASSERTION CHECKS

// get_future_address should fail if the transfer is not committed
// and current address not set
#[rule]
pub fn get_future_address_not_found_fails(e: Env, role_name: Symbol) {
    let role= Role::from_symbol(&e, role_name.clone());
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(get_deadline(&role) == 0 && 
        !e.storage().instance()
        .get::<access_control::storage::DataKey, Address>(&ac.get_key(&role))
        .is_some());
    let _ = FeesCollector::get_future_address(e, role_name);
    cvlr_assert!(false);
}

// get_future_address should fail if the role is not Admin or EmergencyAdmin
#[rule]
pub fn get_future_address_bad_role_fails(e: Env, role_name: Symbol) {
    let role= Role::from_symbol(&e, role_name.clone());
    cvlr_assume!(match role {
            Role::Admin => false,
            Role::EmergencyAdmin => false,
            _ => true,
    });
    let _ = FeesCollector::get_future_address(e, role_name);
    cvlr_assert!(false);
}

// get_future_address should fail if there is no committed address
#[rule]
pub fn get_future_address_no_future_address_fails(e: Env, role_name: Symbol) {
    let role= Role::from_symbol(&e, role_name.clone());
    let ac = AccessControl::new(&e);
    cvlr_assume!(get_deadline(&role) != 0 &&
        !e.storage().instance()
        .get::<access_control::storage::DataKey, Address>(&ac.get_future_key(&role))
        .is_some());
    let _ = FeesCollector::get_future_address(e.clone(), role_name.clone());
    cvlr_assert!(false);
}

//******************* */
// ACCESS CONTROL RULES
//******************* */

// MANAGEMENT.RS
// get_role_safe RULES
// 1. CORRECTNESS RULES

// get_role_safe correctly returns an address for the role except EmergencyPauseAdmin
#[rule]
pub fn get_role_safe_correct(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(match role {
        Role::EmergencyPauseAdmin => false,
        _ => true,
    });
    let result = ac.get_role_safe(role);
    cvlr_assert!(result == e.storage().instance().get(&ac.get_key(role)));
}

// 2. ASSERTION CHECKS

// get_role_safe should fail if requested an address for the EmergencyPauseAdmin role
#[rule]
pub fn get_role_safe_bad_role_fails(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(match role {
        Role::EmergencyPauseAdmin => true,
        _ => false,
    });
    ac.get_role_safe(role);
    cvlr_assert!(false);
}

// get_role RULES
// 1. CORRECTNESS RULES

// get_role correctly returns Admin address
#[rule]
pub fn get_role_correct(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    let result = ac.get_role(role);
    cvlr_assert!(e.storage().instance()
        .get::<access_control::storage::DataKey, Address>(&DataKey::Admin).unwrap() == result);
}

// 2. ASSERTION CHECKS

// get_role should fail if requested an address for any role except Admin 
#[rule]
pub fn get_role_bad_role_fails(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(match role {
        Role::Admin => false,
        _ => true,
    });
    ac.get_role(role);
    cvlr_assert!(false);
}

// get_role should fail if there is no admin set 
#[rule]
pub fn get_role_no_address_fails(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(!e.storage().instance()
        .get::<access_control::storage::DataKey, Address>(&DataKey::Admin)
        .is_some());
    ac.get_role(role);
    cvlr_assert!(false);
}

// set_role_address RULES
// 1. CORRECTNESS RULES

// set_role_address correctly updates an address for the role
#[rule]
pub fn set_role_address_correct(e: Env, role: &Role) {
    let address = nondet_address();
    let ac: AccessControl = AccessControl::new(&e);
    ac.set_role_address(role, &address);
    cvlr_assert!(ac.address_has_role(&address, role));
}

// 2. ASSERTION CHECKS

// set_role_address should fail if trying to update an address for the EmergencyPauseAdmin role
// because it has many users
#[rule]
pub fn set_role_address_bad_role_fails(e: Env, role: &Role) {
    let address = nondet_address();
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(match role {
        Role::EmergencyPauseAdmin => true,
        _ => false,
    });
    ac.set_role_address(role, &address);
    cvlr_assert!(false);
}

// set_role_address should fail if the role requires delay to be updated
#[rule]
pub fn set_role_address_timeout_fails(e: Env, role: &Role) {
    let address = nondet_address();
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(match role {
        Role::Admin => true,
        Role::EmergencyAdmin => true,
        _ => false,
    });
    cvlr_assume!(ac.get_role_safe(role).is_some());
    ac.set_role_address(role, &address);
    cvlr_assert!(false);
}

// (set)get_role_addresses RULES
// 1. CORRECTNESS RULES

// set_role_addresses correctly updates addresses for the EmergencyPauseAdmin role
#[rule]
pub fn set_role_addresses_correct(e: Env, role: &Role, addresses: Vec<Address>) {
    let ac: AccessControl = AccessControl::new(&e);
    ac.set_role_addresses(role, &addresses);
    cvlr_assert!(e.storage()
            .instance()
            .get(&DataKey::EmPauseAdmins)
            .unwrap_or(Vec::new(&e)) == addresses);
}

// get_role_addresses correctly returns all addresses for the role
#[rule]
pub fn set_get_role_addresses_correct(e: Env, role: &Role, addresses: &Vec<Address>) {
    let ac: AccessControl = AccessControl::new(&e);
    ac.set_role_addresses(role, addresses);
    let result = ac.get_role_addresses(role);
    cvlr_assert!(e.storage()
            .instance()
            .get(&DataKey::EmPauseAdmins)
            .unwrap_or(Vec::new(&e)) == result);
    cvlr_assert!(&result == addresses);
}

// 2. ASSERTION CHECKS

// get_role_addresses should fail if requested addresses for any role except EmergencyPauseAdmin 
#[rule]
pub fn get_role_addresses_bad_role_fails(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(match role {
        Role::Admin => true,
        Role::EmergencyAdmin => true,
        Role::RewardsAdmin => true,
        Role::OperationsAdmin => true,
        Role::PauseAdmin => true,
        Role::EmergencyPauseAdmin => false,
    });
    ac.get_role_addresses(role);
    cvlr_assert!(false);
}

// set_role_addresses should fail if trying to update addresses for any role except EmergencyPauseAdmin 
#[rule]
pub fn set_role_addresses_bad_role_fails(e: Env, role: &Role, addresses: &Vec<Address>) {
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(match role {
        Role::Admin => true,
        Role::EmergencyAdmin => true,
        Role::RewardsAdmin => true,
        Role::OperationsAdmin => true,
        Role::PauseAdmin => true,
        Role::EmergencyPauseAdmin => false,
    });
    ac.set_role_addresses(role, addresses);
    cvlr_assert!(false);
}

// ROLE.RS

// from_symbol should fail on incorrect symbol
#[rule]
pub fn from_symbol_bad_role_fails(e: &Env, value: Symbol) {
    cvlr_assume!(value != Symbol::new(e, "Admin") && value != Symbol::new(e, "EmergencyAdmin") &&
        value != Symbol::new(e, "RewardsAdmin") && value != Symbol::new(e, "OperationsAdmin") &&
        value != Symbol::new(e, "PauseAdmin") && value != Symbol::new(e, "EmergencyPauseAdmin"));
    Role::from_symbol(e, value);
    cvlr_assert!(false);
}

// STORAGE.RS

// get_key trivial correctness
#[rule]
pub fn get_key_correct(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    let result = ac.get_key(role);
    cvlr_assert!(match role {
            Role::Admin => result == DataKey::Admin,
            Role::EmergencyAdmin => result == DataKey::EmergencyAdmin,
            Role::RewardsAdmin => result == DataKey::Operator,
            Role::OperationsAdmin => result == DataKey::OperationsAdmin,
            Role::PauseAdmin => result == DataKey::PauseAdmin,
            Role::EmergencyPauseAdmin => result == DataKey::EmPauseAdmins,
    });
}

// get_future_key should fail if requested keys neither for Admin nor for EmergencyAdmin
#[rule]
pub fn get_future_key_correct(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    let result = ac.get_future_key(role);
    cvlr_assert!(match role {
        Role::Admin => result == DataKey::FutureAdmin,
        Role::EmergencyAdmin => result == DataKey::FutureEmergencyAdmin,
        Role::RewardsAdmin => false,
        Role::OperationsAdmin => false,
        Role::PauseAdmin => false,
        Role::EmergencyPauseAdmin => false,
    });
}

// get_future_deadline_key should fail if requested keys neither for Admin nor for EmergencyAdmin
#[rule]
pub fn get_future_deadline_key_correct(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    let result = ac.get_future_deadline_key(role);
        cvlr_assert!(match role {
        Role::Admin => result == DataKey::TransferOwnershipDeadline,
        Role::EmergencyAdmin => result == DataKey::EmAdminTransferOwnershipDeadline,
        Role::RewardsAdmin => false,
        Role::OperationsAdmin => false,
        Role::PauseAdmin => false,
        Role::EmergencyPauseAdmin => false,
    });
}

// TRANSFER.RS
// (put)get_transfer_ownership_deadline RULES
// 1. CORRECTNESS RULES

// put_transfer_ownership_deadline correctly updates deadline for the role
#[rule]
pub fn put_transfer_ownership_deadline_correct(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    let value: u64 = cvlr::nondet();
    ac.put_transfer_ownership_deadline(role, value);
    cvlr_assert!(value == 
        e.storage().instance().get(&ac.get_future_deadline_key(role)).unwrap_or(0));
}

// get_transfer_ownership_deadline correctly returns deadline for the role
#[rule]
pub fn put_get_transfer_ownership_deadline_correct(e: Env, role: &Role) {
    let ac: AccessControl = AccessControl::new(&e);
    let expected: u64 = cvlr::nondet();
    ac.put_transfer_ownership_deadline(role, expected);
    let value = ac.get_transfer_ownership_deadline(role);
    cvlr_assert!(value == 
        e.storage().instance().get(&ac.get_future_deadline_key(role)).unwrap_or(0));
    cvlr_assert!(value == expected);
}

// UTILS.RS
// require_rewards_admin_or_owner RULES

// require_rewards_admin_or_owner is correct
#[rule]
pub fn require_rewards_admin_or_owner_unauthorized_fails(e: &Env, address: &Address) {
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(!ac.address_has_role(address, &Role::Admin)
        && !ac.address_has_role(address, &Role::RewardsAdmin));
    require_rewards_admin_or_owner(e, address);
    cvlr_assert!(false);
}

// require_operations_admin_or_owner is correct
#[rule]
pub fn require_operations_admin_or_owner_unauthorized_fails(e: &Env, address: &Address) {
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(!ac.address_has_role(address, &Role::Admin)
        && !ac.address_has_role(address, &Role::OperationsAdmin));
    require_operations_admin_or_owner(e, address);
    cvlr_assert!(false);
}

// require_pause_admin_or_owner is correct
#[rule]
pub fn require_pause_admin_or_owner_unauthorized_fails(e: &Env, address: &Address) {
    let ac: AccessControl = AccessControl::new(&e);
    cvlr_assume!(!ac.address_has_role(address, &Role::Admin)
        && !ac.address_has_role(address, &Role::PauseAdmin));
    require_pause_admin_or_owner(e, address);
    cvlr_assert!(false);
}

//*************************** */
// RULES FOR REAL BUGS        */
//*************************** */

// When an upgrade is reverted via revert_upgrade, 
// the stored FutureWASM value is not cleared.
// 
// In Emergency mode, apply_upgrade skips deadline checks 
// and will deploy whichever wasm hash remains in storage even one that was previously reverted.
#[rule]
fn reverted_upgrade_can_be_applied_in_emergency(e: Env, reverted_wasm_hash: BytesN<32>) {
    let admin = nondet_address();
    let emergency_admin = nondet_address();
    FeesCollector::commit_upgrade(e.clone(), admin.clone(), reverted_wasm_hash.clone());
    FeesCollector::revert_upgrade(e.clone(), admin.clone());
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin.clone(), true);    
    cvlr_assert!(reverted_wasm_hash != FeesCollector::apply_upgrade(e, admin));
}
