// use core::ops::Add;
// use core::{clone, future};

// use access_control::emergency;
// use soroban_sdk::deploy::DeployerWithAddress;
// use soroban_sdk::xdr::Value;

use access_control::access::AccessControl;
use access_control::interface::TransferableContract;
use access_control::management::{MultipleAddressesManagementTrait, SingleAddressManagementTrait};
use access_control::role::{Role, SymbolRepresentation};
use access_control::storage::{DataKey, StorageTrait};
use access_control::transfer::TransferOwnershipTrait;
use cvlr::clog;
use soroban_sdk::{Address, Env, Vec};

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::{cvlr_satisfy, nondet};
use cvlr_soroban::{is_auth, nondet_address};
use cvlr_soroban_derive::rule;

use crate::certora_specs::util::{get_role_address, get_role_safe_address, is_role};
use crate::certora_specs::ACCESS_CONTROL;
pub use crate::contract::FeesCollector;
use crate::interface::AdminInterface;
use upgrade::interface::UpgradeableContract;
use upgrade::storage::get_future_wasm;
use upgrade::storage::get_upgrade_deadline;
//use upgrade::storage::DataKey;

use crate::certora_specs::utils_ext::fees_collector_funcs::{nondet_func, Action};
use crate::certora_specs::utils_ext::{
    get_transfer_deadline, nondet_role, nondet_wasm, role_to_string,
};

/**
 * These are some example rules to help get started.
 */

#[rule]
pub fn init_admin_sets_admin(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    FeesCollector::init_admin(e, address.clone());
    let addr = get_role_address(Role::Admin);
    // syntax of how to use `clog!`. This is helpful for calltrace when a rule fails.
    clog!(cvlr_soroban::Addr(&addr));
    cvlr_assert!(addr == address);
    cvlr_assert!(is_role(&addr, &Role::Admin))
}

#[rule]
pub fn only_emergency_admin_sets_emergency_mode(e: Env) {
    let address = nondet_address();
    let value: bool = cvlr::nondet();
    cvlr_assume!(!is_role(&address, &Role::EmergencyAdmin));
    FeesCollector::set_emergency_mode(e, address, value);
    cvlr_assert!(false); // should not reach and therefore should pass
}

/**
 * END example rules
 */

/**
 *  RULE: Emergency mode changed => Emergency Admin isnt None
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 *       
 */
#[rule]
pub fn emergency_mode_changed_emergency_admin_is_some(e: Env) {
    let mode_before = FeesCollector::get_emergency_mode(e.clone());

    nondet_func(e.clone());

    let mode_after = FeesCollector::get_emergency_mode(e.clone());

    cvlr_assume!(mode_before != mode_after);

    cvlr_assert!(get_role_safe_address(Role::EmergencyAdmin).is_some());
}

/**
 *  RULE: Emergency mode changed => Emergency admin called set emergency mode
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn emergency_mode_state_transition(e: Env) {
    let emergency_admin = get_role_safe_address(Role::EmergencyAdmin);
    let emergency_mode_before = FeesCollector::get_emergency_mode(e.clone());

    let action = nondet_func(e.clone());

    let emergency_mode_after = FeesCollector::get_emergency_mode(e.clone());

    clog!(emergency_mode_before);
    clog!(emergency_mode_after);

    cvlr_assume!(emergency_mode_before != emergency_mode_after);

    match emergency_admin {
        Some(emerg_admin) => {
            cvlr_assert!(action == Action::SetEmergencyMode && is_auth(emerg_admin))
        }
        None => cvlr_assert!(false), // Cant change emergency mode if theres no emergency admin
    }
}

/**
 *  RULE: Admin not none => init_admin reverts
    Tested: Yes
    Bugs: No
    Note:
*/
#[rule]
pub fn no_init_if_admin_exists(e: Env) {
    let admin_address = get_role_safe_address(Role::Admin);
    cvlr_assume!(admin_address.is_some());

    FeesCollector::init_admin(e.clone(), nondet_address());

    cvlr_assert!(false); // Should never get here, so it must be true.
}

/**
 * ROLE TRANSFER LOGIC
 */

/**
 *  RULE: Every role has only 1 address, unless has_many_users  
 *  Tested: Yes.
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn one_address_per_role() {
    let role = nondet_role();
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    let other_address = nondet_address();
    clog!(cvlr_soroban::Addr(&other_address));

    cvlr_assume!(!role.has_many_users());

    // assume both addresses have the same role:
    cvlr_assume!(is_role(&address, &role) && is_role(&other_address, &role));

    cvlr_assert!(address == other_address);
}

/**
 *  RULE: Role changed => apply transfer was called or InitAdmin was called if role was none.
 *  Tested: Yes
 *  Bugs: No
 *  Note: role.has_many_users() is not relevant here because functionality of transfering roles with many users isnt implemented in FeesCollector.
*/
#[rule]
pub fn role_only_changes_if_apply_transfer(e: Env) {
    let role = nondet_role();
    role_to_string(&role);
    let address_before = get_role_safe_address(role.clone());

    // Execute operation
    let action = nondet_func(e.clone());

    let address_after = get_role_safe_address(role.clone());

    cvlr_assume!(address_before != address_after);

    cvlr_assert!(
        action == Action::ApplyTransfer
            || (address_before.is_none() && action == Action::InitAdmin)
    );
}

/**
 *  RULE: if revert called => apply does nothing
 *  Tested: Yes  
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn cant_apply_transfer_if_revert_called(e: Env) {
    let role = nondet_role();

    FeesCollector::revert_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));
    FeesCollector::apply_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));

    cvlr_assert!(false); // shouldnt reach
}

/**
 *  RULE: Apply called and address before wasnt none =>  delay <= blocktimestamp
 *  Tested: Yes
 *  Bugs: No
 *  Note: This rule doesnt check role.has_many_users() because it is not relevant for the FeesCollector.
*/
#[rule]
pub fn role_cant_transfer_within_deadline(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);
    let address_before = get_role_safe_address(role.clone());

    let delay = acc_ctrl.get_transfer_ownership_deadline(&role);
    // cvlr_assume!(delay > 0 && address_before.is_some());
    cvlr_assume!(delay > e.ledger().timestamp() && address_before.is_some());

    // Execute apply
    FeesCollector::apply_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));
    
    clog!(delay);
    clog!(e.ledger().timestamp());  

    // cvlr_assert!(e.ledger().timestamp() >= delay);
    cvlr_assert!(false); // Should not reach, should pass
}

/**
 *  RULE: If I am an Admin, I can transfer my role
 *  Tested: Yes
 *  Bugs: YES - admin cannot transfer his role to anyone due to Role::from_symbol bug
 *  Note:
*/
#[rule]
pub fn admin_can_transfer_fees_collector(e: Env) {
    let role = Role::Admin;

    let address_before = get_role_safe_address(role.clone());

    let action = nondet_func(e.clone());
    cvlr_assume!(action != Action::InitAdmin);

    let address_after = get_role_safe_address(role.clone());

    cvlr_satisfy!(address_before != address_after);
}

/**
 *  RULE: If I am an Emergency admin, I can transfer my role
 *  Tested: Yes
 *  Bugs: No
 *  Note: redundant rule, but included for completeness
*/
#[rule]
pub fn emergency_admin_can_transfer(e: Env) {
    let role = Role::EmergencyAdmin;

    let address_before = get_role_safe_address(role.clone());

    nondet_func(e.clone());

    let address_after = get_role_safe_address(role.clone());

    cvlr_satisfy!(address_before != address_after);
}

/**
 *  RULE: Cant transfer role to None
 *  Tested: Yes
 *  Bugs: No
 *  Note: This rule doesnt check role.has_many_users() because it is not relevant for the FeesCollector.
*/
#[rule]
pub fn cant_transfer_role_to_none(e: Env) {
    let role = nondet_role();
    role_to_string(&role);

    let address_before = get_role_safe_address(role.clone());

    //cvlr_assume!(address_before.is_some());

    nondet_func(e.clone());
    //cvlr_assume!(action != Action::InitAdmin);

    let address_after = get_role_safe_address(role.clone());

    // Assume the address changed
    cvlr_assume!(address_before != address_after);

    cvlr_assume!(address_after.is_none());
    cvlr_assert!(false); // Shouldnt reach due to vacuity, should pass
}

/**
 *  RULE: If role has deadline => role.is_transfer_delayed
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn role_has_deadline_is_transfer_delayed() {
    let role = nondet_role();
    //let role = Role::Admin;
    get_transfer_deadline(&role); // should revert for roles without deadline

    cvlr_assert!(role.is_transfer_delayed());
}

/**
 *  RULE: If role.is_transfer_delayed => role has deadline
 *  Tested: Yes
 *  Bugs: No
 *  Note: The other direction of the rule above   
*/
#[rule]
pub fn role_is_transfer_delayed_has_deadline() {
    let role = nondet_role();
    cvlr_assume!(role.is_transfer_delayed());
    //let role = Role::Admin;
    get_transfer_deadline(&role);

    cvlr_assert!(true); // Should always reach.
}

/**
 *  RULE: Transfering a role doesnt affect the other roles when both dont have many users  
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 */
#[rule]
pub fn one_role_at_a_time_both_not_has_many_fees_collector(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let other_role = nondet_role();
    role_to_string(&role);
    role_to_string(&other_role);

    let address_before = acc_ctrl.get_role_safe(&role);
    let other_address_before = acc_ctrl.get_role_safe(&other_role);

    cvlr_assume!(address_before != other_address_before);

    nondet_func(e.clone());

    let address_after = acc_ctrl.get_role_safe(&role);
    let other_address_after = acc_ctrl.get_role_safe(&other_role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!(other_address_before == other_address_after);
}

/**
 *  RULE: Transfering a role doesnt affect the other roles when only transfering role.has_many_users
 *  Tested: Yes
 *  Bugs: Yes - fails due to the Vec.contains() bug
 *  Note:
 */
#[rule]
pub fn one_role_at_a_time_transfering_role_has_many_users_fees_collector(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let other_role = nondet_role();
    role_to_string(&role);
    role_to_string(&other_role);

    let addresses_before = acc_ctrl.get_role_addresses(&role);
    let other_address_before = acc_ctrl.get_role_safe(&other_role);

    nondet_func(e.clone());

    let addresses_after = acc_ctrl.get_role_addresses(&role);
    let other_address_after = acc_ctrl.get_role_safe(&other_role);

    cvlr_assume!((addresses_before.len()>0 || addresses_after.len()>0) && addresses_before != addresses_after);

    cvlr_assert!(other_address_before == other_address_after);
}

/**
 *  RULE: Transfering a role doesnt affect the other roles when only other_role.has_many_users
 *  Tested: Yes
 *  Bugs: Yes - fails due to the Vec.contains() bug
 *  Note:
 */
#[rule]
pub fn one_role_at_a_time_other_role_has_many_users_fees_collector(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let other_role = nondet_role();
    role_to_string(&role);
    role_to_string(&other_role);

    let address_before = acc_ctrl.get_role_safe(&role);
    let other_addresses_before = acc_ctrl.get_role_addresses(&other_role);

    nondet_func(e.clone());

    let address_after = acc_ctrl.get_role_safe(&role);
    let other_addresses_after = acc_ctrl.get_role_addresses(&other_role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!((other_addresses_before == other_addresses_after) ||
                (other_addresses_before.len() == 0 && other_addresses_after.len() == 0));
}

/**
 *  RULE: Transfering a role doesnt affect the other roles when both roles have many users
 *  Tested: Yes
 *  Bugs: Yes - fails due to the Vec.contains() bug
 *  Note: This rule is vacuous because there is only one role that has many users. But it is
 *        included for completeness.
 */
#[rule]
pub fn one_role_at_a_time_both_has_many_users_fees_collector(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let other_role = nondet_role();
    role_to_string(&role);
    role_to_string(&other_role);

    let addresses_before = acc_ctrl.get_role_addresses(&role);
    let other_addresses_before = acc_ctrl.get_role_addresses(&other_role);

    cvlr_assume!((addresses_before.len()>0 || other_addresses_before.len()>0) && addresses_before != other_addresses_before); // Currently renders the rule vacuous.

    nondet_func(e.clone());

    let addresses_after = acc_ctrl.get_role_addresses(&role);
    let other_addresses_after = acc_ctrl.get_role_addresses(&other_role);

    cvlr_assume!((addresses_before.len()>0 || addresses_after.len()>0) && addresses_before != addresses_after);

    cvlr_assert!(   (other_addresses_before == other_addresses_after) ||
                    (other_addresses_before.len() == 0 && other_addresses_after.len() == 0));
}

/**
 *  RULE: Deadline changed => (from 0 => deadlline>currenttimestamp)
 *                          (from deadline =! 0 => deadline = 0)   
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn deadline_state_transition_transfer(e: Env) {
    let role = nondet_role();

    let deadline_before = get_transfer_deadline(&role);

    //Execute Operation
    nondet_func(e.clone());

    let deadline_after = get_transfer_deadline(&role);

    //assume deadline changed
    cvlr_assume!(deadline_before != deadline_after);

    cvlr_assert!(
        (deadline_before == 0 && deadline_after > e.ledger().timestamp())
            || (deadline_before != 0 && deadline_after == 0)
    );
}

/**
 *  RULE: Deadline changed to nonzero value => commit was called
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn deadline_changed_due_to_commit(e: Env) {
    let role = nondet_role();
    let deadline_before = get_transfer_deadline(&role);

    //Execute Operation
    let action = nondet_func(e.clone());

    let deadline_after = get_transfer_deadline(&role);

    // assume deadline changed to nonzero value
    cvlr_assume!(deadline_before != deadline_after && deadline_after > 0);

    cvlr_assert!(action == Action::CommitTransfer);
}

/**
 *  RULE: Deadline changed to zero value => apply or revert was called
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn deadline_changed_due_to_revert_or_apply(e: Env) {
    let role = nondet_role();
    let deadline_before = get_transfer_deadline(&role);

    //Execute Operation
    let action = nondet_func(e.clone());

    let deadline_after = get_transfer_deadline(&role);

    // assume deadline changed to nonzero value
    cvlr_assume!(deadline_before != deadline_after && deadline_after == 0);

    cvlr_assert!(action == Action::ApplyTransfer || action == Action::RevertTransfer);
}

/**
 *  RULE: Cannot commit if deadline > 0
 *  Tested: Yes.
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn cant_commit_before_deadline_transfer(e: Env) {
    let role = nondet_role();
    let deadline: u64 = get_transfer_deadline(&role);

    cvlr_assume!(deadline > 0);

    FeesCollector::commit_transfer_ownership(
        e.clone(),
        nondet_address(),
        role.as_symbol(&e),
        nondet_address(),
    );

    cvlr_assert!(false); // Should not reach -> should pass
}

/**
 *  RULE: Transfer deadline can only change to > now() or zero
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 *       
*/
#[rule]
pub fn deadline_valid_states_fees_collector(e: Env) {
    let role = nondet_role();
    role_to_string(&role);

    let deadline_before = get_transfer_deadline(&role);

    nondet_func(e.clone());

    let deadline_after = get_transfer_deadline(&role);

    cvlr_assume!(deadline_before != deadline_after);

    cvlr_assert!(deadline_after == 0 || deadline_after > e.ledger().timestamp());
}

/**
 *  RULE: Only Admin can call commit, apply, revert for transfer or upgrade
 *  Tested: Yes
 *  Bugs: No
 *  Note:    
*/
#[rule]
pub fn only_admin_transfers_roles_or_upgrades(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();

    //Execute Operation
    let action = nondet_func(e.clone());
    cvlr_assume!(
        action == Action::CommitTransfer
            || action == Action::ApplyTransfer
            || action == Action::RevertTransfer
            || action == Action::CommitUpgrade
            || action == Action::ApplyUpgrade
            || action == Action::RevertUpgrade
    );

    let admin: Option<Address> = e.storage().instance().get(&acc_ctrl.get_key(&Role::Admin));
    //If there is an Admin => he should be signer;
    //If there is no admin => commit could not have been done by the admin.

    match admin {
        Some(admin) => cvlr_assert!(is_auth(admin)),
        None => cvlr_assert!(false),
    }

    // cvlr_satisfy!(true)
}

/**
 *  RULE: Role changed => Must be Only Admin or Emergency Admin.
 *  Tested: Yes
 *  Bugs: No
 *  Reason: This rule doesnt check role.has_many_users() because it is not relevant for the FeesCollector.
*/
#[rule]
pub fn only_admin_or_emergency_admin_be_transfered(e: Env) {
    let role = nondet_role();
    let add_before = get_role_safe_address(role.clone());

    //Exucute operation
    nondet_func(e.clone());

    let add_after = get_role_safe_address(role.clone());

    cvlr_assume!(add_after != add_before);

    cvlr_assert!(
        role.as_symbol(&e) == Role::Admin.as_symbol(&e)
            || role.as_symbol(&e) == Role::EmergencyAdmin.as_symbol(&e)
    );
}

/**
 *  RULE: Contract address cant have role. Its more important for Admin or Emergency Admin.
 *  Tested: Yes
 *  Bugs: Yes
 *  Note: Contract can be assigned a role. Its a bug. Contract could lose functionality if
 *        Admin and/or Emergency Admin are assinged to contract address.
*/
#[rule]
pub fn contract_cant_have_role(e: Env) {
    let role = nondet_role();
    role_to_string(&role);
    let contract_address = e.current_contract_address();  
    clog!(cvlr_soroban::Addr(&contract_address));

    let address_before = get_role_safe_address(role.clone());

    // Execute operation
    nondet_func(e.clone());
    
    let address_after = get_role_safe_address(role.clone());
    
    // Assume the role changed addresses
    cvlr_assume!(address_before != address_after);

    cvlr_assert!(address_after.unwrap() != contract_address);
}


/**
 *  RULE: If future address changed => someone called commit
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn future_address_state_transition_fees_collector(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);

    let future_address_before: Option<Address> =
        e.storage().instance().get(&acc_ctrl.get_future_key(&role));

    // Execute operation
    let action = nondet_func(e.clone());

    let future_address_after: Option<Address> =
        e.storage().instance().get(&acc_ctrl.get_future_key(&role));

    // Assume future address changed after the operation
    cvlr_assume!(future_address_before != future_address_after);

    // Assert the only operation that changed it is the commit transfer
    cvlr_assert!(action == Action::CommitTransfer);
}

/**
 *  RULE: If future address changed => deadlne changed
 *  Tested:
 *  Bugs:
 *  Note:   
*/
#[rule]
pub fn future_address_changed_deadline_changed_fees_collector(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);

    let future_address_before: Option<Address> =
        e.storage().instance().get(&acc_ctrl.get_future_key(&role));
    let deadline_before = get_transfer_deadline(&role);

    //Execute Operation
    nondet_func(e.clone());

    let future_address_after = e.storage().instance().get(&acc_ctrl.get_future_key(&role));
    let deadline_after = get_transfer_deadline(&role);

    // Assume future address changed after the operation
    cvlr_assume!(future_address_before != future_address_after);

    // Assert the only operation that changed it is the commit transfer
    cvlr_assert!(deadline_before != deadline_after);
    // cvlr_satisfy!(true);
}

/**
 *  RULE: Future address cant become None
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn future_address_cant_become_none_fees_collector(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let future_address_before: Option<Address> =
        e.storage().instance().get(&acc_ctrl.get_future_key(&role));

    nondet_func(e.clone());

    let future_address_after: Option<Address> =
        e.storage().instance().get(&acc_ctrl.get_future_key(&role));

    cvlr_assume!(future_address_before != future_address_after);

    cvlr_assert!(future_address_after.is_some());
}
/*---------------------------------------------------------------------------------------------- */

/**
 * CONTRACT UPGRADE LOGIC
 */

/**
 *  RULE: If future wasm changed => Admin called commit upgrade && didnt change to None.
 *  Tested: Yes.
 *  Bugs: no
 *  Note:  Not checking for admin due to the only_admin_transfers_roles_or_upgrades rule
*/
#[rule]
pub fn future_wasm_state_transition(e: Env) {
    let future_wasm_before = upgrade::storage::get_future_wasm(&e);

    // Execute operation
    let action = nondet_func(e.clone());

    let future_wasm_after = upgrade::storage::get_future_wasm(&e);

    // Assume future wasm changed after the operation
    cvlr_assume!(future_wasm_before != future_wasm_after);

    cvlr_assert!(future_wasm_after.is_some() && action == Action::CommitUpgrade);
}

/**
 *  RULE: Future wasm changed => deadline changed
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn future_wasm_changed_deadline_changed(e: Env) {
    let future_wasm_before = upgrade::storage::get_future_wasm(&e);
    let deadline_before = upgrade::storage::get_upgrade_deadline(&e);

    nondet_func(e.clone());

    let future_wasm_after = upgrade::storage::get_future_wasm(&e);
    let deadline_after = upgrade::storage::get_upgrade_deadline(&e);

    cvlr_assume!(future_wasm_before != future_wasm_after);

    cvlr_assert!(deadline_before != deadline_after);
}

/**
 *  RULE: Future wasm cant become None
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn future_wasm_cant_be_none(e: Env) {
    let future_wasm_before = upgrade::storage::get_future_wasm(&e);

    nondet_func(e.clone());

    let future_wasm_after = upgrade::storage::get_future_wasm(&e);

    cvlr_assume!(future_wasm_before != future_wasm_after);

    cvlr_assert!(future_wasm_after.is_some());
}

/**
 *  RULE: Deadline changed to nonzero value => commitupgrade was called
 *  Tested: Yes
 *  Bugs: No
 *  Note: validated by changing CommitUpgrade to RevertUpgrade
*/
#[rule]
pub fn deadline_changed_due_to_commit_upgrade(e: Env) {
    let deadline_before = get_upgrade_deadline(&e);

    //Execute Operation
    let action = nondet_func(e.clone());

    let deadline_after = get_upgrade_deadline(&e);

    // assume deadline changed to nonzero value
    cvlr_assume!(deadline_before != deadline_after && deadline_after > 0);

    cvlr_assert!(action == Action::CommitUpgrade);
}

/**
 *  RULE: Deadline changed to zero value => applyUpgrade or revertUpgrade was called
 *  Tested: Yes
 *  Bugs: No
 *  Note: validated by removing applyUpgrade
*/
#[rule]
pub fn deadline_changed_due_to_revert_or_apply_upgrade(e: Env) {
    let deadline_before = get_upgrade_deadline(&e);

    //Execute Operation
    let action = nondet_func(e.clone());

    let deadline_after = get_upgrade_deadline(&e);

    // assume deadline changed to nonzero value
    cvlr_assume!(deadline_before != deadline_after && deadline_after == 0);

    cvlr_assert!(action == Action::RevertUpgrade || action == Action::ApplyUpgrade);
}

/**
 *  RULE: Deadline changed => (from 0 => deadline>currenttimestamp)
 *                          (from deadline =! 0 => deadline = 0)
 *  Tested: Yes
 *  Bugs: No
 *  Note: validated by removing applyUpgrade
*/
#[rule]
pub fn deadline_state_transition_upgrade(e: Env) {
    let deadline_before = get_upgrade_deadline(&e);

    //Execute Operation
    nondet_func(e.clone());

    let deadline_after = get_upgrade_deadline(&e);

    //assume deadline changed
    cvlr_assume!(deadline_before != deadline_after);

    cvlr_assert!(
        (deadline_before == 0 && deadline_after > e.ledger().timestamp())
            || (deadline_before != 0 && deadline_after == 0)
    );
}
/**
 *  RULE: Cannot commit if deadline != 0
 *  Tested: Yes.
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn cant_commit_if_deadline_nonzero_upgrade(e: Env) {
    let deadline: u64 = get_upgrade_deadline(&e);

    cvlr_assume!(deadline != 0);

    FeesCollector::commit_upgrade(e.clone(), nondet_address(), nondet_wasm());

    cvlr_assert!(false); // Should not reach -> should pass
}

/*------------------------------------------------------------------------------------------ */
/**
 * UNIT TESTS
 */

/**
 * Function: commit_transfer_ownership
 *
 * Functinality
 *  - Only admin
 *  - Sets future wasm
 *  - Sets deadline
 *
 * https://prover.certora.com/output/7145022/5f92ae1a4b8f403ea06a65c3c01678ca/?anonymousKey=133f486ffb954a83e8bc07768d52ec8704331af7&params=%7B%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3Anull%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */

#[rule]
pub fn commit_upgrade_integrity(e: Env) {
    let admin = get_role_safe_address(Role::Admin);
    let new_wasm = nondet_wasm();

    FeesCollector::commit_upgrade(e.clone(), nondet_address(), new_wasm.clone());

    let deadline = get_upgrade_deadline(&e);
    let future_wasm = upgrade::storage::get_future_wasm(&e).unwrap();

    match admin {
        Some(admin) => cvlr_assert!(
            future_wasm == new_wasm
                && is_auth(admin)
                && deadline == e.ledger().timestamp() + 3 * 86400
        ),
        None => cvlr_assert!(false), // Cant commit upgrade if there is no admin
    }
}

/**
 * Function: apply_upgrade
 *
 * Functinality
 *  - Only admin
 *  - returns the new contract wasm == futureWasm
 *  - Sets deadline to 0
 *  - Ignores deadline if emergency mode is on
 *
 * https://prover.certora.com/output/7145022/f2c21effbe9e4699828b3c644565b40e/?anonymousKey=288043d940c5f014faf51549bd4979e3fa39126d&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */

#[rule]
pub fn apply_upgrade_integrity(e: Env) {
    let emergency_mode = FeesCollector::get_emergency_mode(e.clone());

    let admin = get_role_safe_address(Role::Admin);
    let future_wasm = get_future_wasm(&e).unwrap();
    let deadline_before = get_upgrade_deadline(&e);

    let new_wasm = FeesCollector::apply_upgrade(e.clone(), nondet_address());

    let deadline_after = get_upgrade_deadline(&e);

    clog!(emergency_mode);
    clog!(deadline_before);
    clog!(deadline_after);
    clog!(e.ledger().timestamp());
    clog!(cvlr_soroban::Addr(&admin.as_ref().unwrap()));

    match admin {
        Some(admin) => {
            cvlr_assert!(
                is_auth(admin)
                    && future_wasm == new_wasm
                    && deadline_after == 0
                    && (emergency_mode
                        || (!emergency_mode && deadline_before <= e.ledger().timestamp()))
            )
        }
        None => cvlr_assert!(false), // Cant apply without admin
    }
}

/**
 * Function: revert_upgrade
 *
 * Functinality
 *  - Only admin
 *  - Sets deadline to 0
 *
 * https://prover.certora.com/output/7145022/6f59f450cae14b73bb2c73470738b8f1/?anonymousKey=6260df8aa028abb0f5e655ac987bc0f157309724&params=%7B%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3Anull%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */

#[rule]
pub fn revert_upgrade_integrity(e: Env) {
    let admin = get_role_safe_address(Role::Admin);

    FeesCollector::apply_upgrade(e.clone(), nondet_address());

    let deadline = get_upgrade_deadline(&e);

    match admin {
        Some(admin) => cvlr_assert!(deadline == 0 && is_auth(admin)),
        None => cvlr_assert!(false), // Cant revert without admin
    };
}

/**
 * Function: set_emergency_mode
 *
 * Functinality
 *  - Only Emergency admin
 *  - Sets mode to bool value
 *
 * https://prover.certora.com/output/7145022/3e5afc1498ba4b70817d5e96c7cd11f8/?anonymousKey=7ed4a64a573467a0123b0c0dbd749322a7bfd2e2&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */

#[rule]
pub fn set_emergency_mode_integrity(e: Env) {
    let emergency_admin = get_role_safe_address(Role::EmergencyAdmin);
    let value: bool = nondet();

    FeesCollector::set_emergency_mode(e.clone(), nondet_address(), value);

    let value_after = FeesCollector::get_emergency_mode(e.clone());

    match emergency_admin {
        Some(emergency_admin) => cvlr_assert!(is_auth(emergency_admin) && value_after == value),
        None => cvlr_assert!(false), // Cant set emergency mode without emergency admin
    };
}

/**
 * Functin: commit_transfer_ownership
 *
 * Functinality
 *  - Only admin
 *  - Sets future address
 *  - Sets deadline
 *
 * https://prover.certora.com/output/7145022/24f5b7e0fc5d4d66afad6e1121023cac/?anonymousKey=eb6e272efca93bcb292ea3c5e3531a6006f31569&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22file%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *
 * Bug: Doesnt work with Admin
 */
#[rule]
pub fn commit_transfer_ownership_integrity(e: Env) {
    let admin = get_role_safe_address(Role::Admin);
    let role = nondet_role();
    //let role = Role::Admin;
    let future_add = nondet_address();

    FeesCollector::commit_transfer_ownership(
        e.clone(),
        nondet_address(),
        role.clone().as_symbol(&e),
        future_add.clone(),
    );

    let deadline = get_transfer_deadline(&role);
    let future_add_after = FeesCollector::get_future_address(e.clone(), role.as_symbol(&e));
    clog!(cvlr_soroban::Addr(&future_add_after));

    match admin {
        Some(admin) => {
            cvlr_assert!(
                is_auth(admin)
                    && future_add_after == future_add
                    && deadline
                        == e.ledger().timestamp() + access_control::constants::ADMIN_ACTIONS_DELAY
            )
        }
        None => cvlr_assert!(false), // Cant commit without admin
    }

    //cvlr_satisfy!(true);
}

/**
 * Functin: apply_transfer_ownership
 *
 * Functinality
 *  - Only admin
 *  - Sets role to future address
 *  - Sets deadline == 0
 *
 * https://prover.certora.com/output/7145022/5219adadb51d4ceaa7844da5f1906039/?anonymousKey=c5f14aabcc99cdce026116024d3a519a26d45d04&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn apply_transfer_ownership_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let admin = get_role_safe_address(Role::Admin);
    let role = nondet_role();
    let role_key = acc_ctrl.get_future_key(&role);
    let future_add: Address = e.storage().instance().get(&role_key).unwrap();    
    role_to_string(&role);  

    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);
    let address_before = acc_ctrl.get_role_safe(&role);

    FeesCollector::apply_transfer_ownership(
        e.clone(),
        nondet_address(),
        role.clone().as_symbol(&e),
    );

    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    clog!(deadline_before);
    clog!(deadline_after);
    clog!(e.ledger().timestamp());

    let current_address: Address = e.storage().instance().get(&role_key).unwrap();
    clog!(cvlr_soroban::Addr(&current_address));
    clog!(cvlr_soroban::Addr(&future_add));

    match admin {
        Some(admin) => cvlr_assert!(
                is_auth(admin)
                && deadline_after == 0
                && future_add == current_address
                && ((address_before.is_some() && deadline_before <= e.ledger().timestamp()) || address_before.is_none())    
        ),
        None => cvlr_assert!(false), // Cant apply transfer without admin
    }
    //cvlr_satisfy!(true)
}

/**
 * Function: revert_transfer_ownership
 *
 * Functinality
 *  - Only admin
 *  - Sets deadline == 0
 *
 * https://prover.certora.com/output/7145022/bd4adbcd5d064757a3e001653ed70713/?anonymousKey=d30be73817f77f1efa1a5aa1996701c2fbc379d9&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn revert_transfer_ownership_integrity(e: Env) {
    let admin = get_role_safe_address(Role::Admin);
    let role = nondet_role();

    FeesCollector::revert_transfer_ownership(
        e.clone(),
        nondet_address(),
        role.clone().as_symbol(&e),
    );

    let deadline = get_transfer_deadline(&role);

    match admin {
        Some(admin) => cvlr_assert!(deadline == 0 && is_auth(admin)),
        None => cvlr_assert!(false), // Cant revert without admin
    };
}

/**
 * Function: get_future_address for Admin role
 *              wrote the rule only for admin as proof of bug
 *
 * Functinality
 *  - gets the future address
 *
 * Bug: This rule is vacuos due to the From_symbol bug for admin.
 *
 * Proof: https://prover.certora.com/output/7145022/a0a5735ee40e42d2bc60046fe64dc613/?anonymousKey=07b078fc93cd80fea26a2bbd9c816aa1ebf018ab&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn get_future_address_integrity_admin(e: Env) {
    let role = Role::Admin;
    let access_control = AccessControl::new(&e);
    // Assume the future address is applicable
    //cvlr_assume!(get_transfer_deadline(&role)>0);
    //access_control.get_future_address(&role);
    let future_key = access_control.get_future_key(&role);
    let true_future_add: Address = e.storage().instance().get(&future_key).unwrap();

    let future_from_fees = FeesCollector::get_future_address(e.clone(), role.clone().as_symbol(&e));

    role_to_string(&role);
    clog!(cvlr_soroban::Addr(&true_future_add));
    clog!(cvlr_soroban::Addr(&future_from_fees));

    //clog!(&access_control.get_transfer_ownership_deadline(&role));
    cvlr_satisfy!(true);
}

/**
 * Function: get_future_address for nondet role
 *
 * Functinality
 *  - gets the future address
 *
 * https://prover.certora.com/output/7145022/db145f6e5ce54f89bedf76e84ae36080/?anonymousKey=fb450ad9ed27ad7498b5723591319a5fc0ae73ab&params=%7B%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3Anull%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn get_future_address_integrity_fees_collector(e: Env) {
    let role = nondet_role();
    role_to_string(&role);
    
    let acc_ctrl = AccessControl::new(&e);
    // Assume someone called commit
    cvlr_assume!(get_transfer_deadline(&role) > 0);
    //acc_ctrl.get_future_address(&role);
    let future_key = acc_ctrl.get_future_key(&role);
    let true_future_add: Address = e.storage().instance().get(&future_key).unwrap();
    
    let future_from_fees = FeesCollector::get_future_address(e.clone(), role.clone().as_symbol(&e));
    
    clog!(cvlr_soroban::Addr(&true_future_add));
    clog!(cvlr_soroban::Addr(&future_from_fees));
    
    //clog!(&acc_ctrl.get_transfer_ownership_deadline(&role));
    cvlr_assert!(true_future_add == future_from_fees);
}

/**
 * Function: get_emergency_mode
 *
 * Functinality
 *  - gets the emergency mode
 *
 * https://prover.certora.com/output/7145022/af20eb475f4048a9b21241215309a6bd/?anonymousKey=f1ff4a3b4fb78e9d356eed602b30b125d2457dde&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn get_emergency_mode_integrity(e: Env) {
    let emergency_mode_key = access_control::storage::DataKey::EmergencyMode;
    let emergency_mode_from_fees = FeesCollector::get_emergency_mode(e.clone());
    let true_emergency_mode: bool = e.storage().instance().get(&emergency_mode_key).unwrap();
    
    cvlr_assert!(true_emergency_mode == emergency_mode_from_fees);
}

/** Rules proving the From_symbol and Vec comparison bugs*/

/**
 * RULE: Comparison between two vectors of addresses when possibly both are empty
 *
 * This rule is to prove the Vec comparison bug
 */
#[rule]
pub fn compare_two_poissibly_empty_vectors() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();

    let role = Role::EmergencyPauseAdmin;
    let vec3 = acc_ctrl.get_role_addresses(&role);
    let vec5 = acc_ctrl.get_role_addresses(&role);  

    cvlr_assert!(vec3 == vec5);
}

/**
 * RULE: Comparison between two vectors of addresses when at least one is not empty
 * 
 * This rule is to prove the Vec comparison bug
 */
#[rule]
pub fn compare_two_vectors_at_least_one_isnt_empty(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();

    let role = Role::EmergencyPauseAdmin;
    // let vec3 = acc_ctrl.get_role_addresses(&role);
    // let vec5 = acc_ctrl.get_role_addresses(&role);  

    let vec3 = e.storage().instance().get::<DataKey, Vec<Address>>(&acc_ctrl.get_key(&role)).unwrap_or(Vec::new(&e));
    let vec5 = e.storage().instance().get::<DataKey, Vec<Address>>(&acc_ctrl.get_key(&role)).unwrap_or(Vec::new(&e));

    cvlr_assume!(vec3.len() > 0 || vec5.len() > 0);

    cvlr_assert!(vec3 == vec5);
}

/**
 *  RULE: Role.as_symbol reverts for admin
 * 
 * This rule is to prove the from_symbol bug
 *  Bugs: rule fails, therefore, from_symbol is unreachable for admin
*/
#[rule]
pub fn role_from_symbol_reverts_for_admin(e: Env) {
    Role::from_symbol(&e, Role::Admin.as_symbol(&e));

    cvlr_satisfy!(true); 
}

