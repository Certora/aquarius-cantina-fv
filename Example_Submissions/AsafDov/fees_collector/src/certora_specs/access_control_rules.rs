use crate::certora_specs::utils_ext::access_control_funcs::{nondet_func, Action};
use crate::certora_specs::utils_ext::{get_transfer_deadline, role_to_string};
use crate::certora_specs::util::{is_role};
use access_control::access::AccessControlTrait;
use access_control::management::{MultipleAddressesManagementTrait, SingleAddressManagementTrait};
use access_control::role::{Role, SymbolRepresentation};
use access_control::storage::{DataKey, StorageTrait};
use access_control::transfer::TransferOwnershipTrait;
use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::{clog, cvlr_satisfy, nondet};
use cvlr_soroban::{nondet_address, nondet_vec};
use cvlr_soroban_derive::rule;
use soroban_sdk::{ Address, Env, Vec};

use super::utils_ext::nondet_role;
use super::ACCESS_CONTROL;

// example for unit test rule for access control
#[rule]
pub fn set_emergency_mode_success(e: Env) {
    let value: bool = cvlr::nondet();
    access_control::emergency::set_emergency_mode(&e, &value);
    cvlr_assert!(access_control::emergency::get_emergency_mode(&e) == value);
}

/**
 *  RULE: Emergency mode changed => set_emergency_mode called
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn emergency_mode_state_transition_access_control(e: Env) {
    let mode_before = access_control::emergency::get_emergency_mode(&e);

    let action = nondet_func(e.clone());

    let mode_after = access_control::emergency::get_emergency_mode(&e);

    cvlr_assume!(mode_before != mode_after);

    cvlr_assert!(action == Action::SetEmergencyMode);
}

/**
 *  RULE: Role.has_many_user => get_role_safe reverts
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn role_has_many_users_get_role_safe_reverts() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);

    cvlr_assume!(role.has_many_users());

    acc_ctrl.get_role_safe(&role);

    cvlr_assert!(false); //shouldnt reach
}

/**
 *  RULE: Role.has_many_user => get_role_address reverts
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn role_has_many_users_get_role_reverts() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);

    cvlr_assume!(role.has_many_users());

    acc_ctrl.get_role(&role);
    cvlr_assert!(false); //shouldnt reach
}

/**
 *  RULE: Role.has_many_user => set_role_address reverts
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn role_has_many_users_set_role_address_reverts() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);

    cvlr_assume!(role.has_many_users());

    acc_ctrl.set_role_address(&role, &nondet_address());

    cvlr_assert!(false); //shouldnt reach
}

/**
 *  RULE: !Role.has_many_user => set_role_addresses reverts
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 *       
*/
#[rule]
pub fn role_not_has_many_users_set_role_addresses_reverts() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);

    cvlr_assume!(!role.has_many_users());

    acc_ctrl.set_role_addresses(&role, &nondet_vec());

    cvlr_assert!(false); //shouldnt reach
}

/**
 *  RULE: !Role.has_many_user => get_role_addresses reverts
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 *       
*/
#[rule]
pub fn role_not_has_many_users_get_role_addresses_reverts() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);

    cvlr_assume!(!role.has_many_users());

    acc_ctrl.get_role_addresses(&role);

    cvlr_assert!(false); //shouldnt reach
}

/**
 *  RULE: Future address changed => deadline changed
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn future_address_changed_deadline_changed_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let future_before = acc_ctrl.get_future_address(&role);
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    nondet_func(e.clone());

    let future_after = acc_ctrl.get_future_address(&role);
    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assume!(future_before != future_after);

    cvlr_assert!(deadline_before != deadline_after);
}

/**
 *  RULE: Future address changed => commit was called
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn future_address_state_transition_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let future_before = acc_ctrl.get_future_address(&role);

    let action = nondet_func(e.clone());

    let future_after = acc_ctrl.get_future_address(&role);

    cvlr_assume!(future_before != future_after);

    cvlr_assert!(action == Action::CommitTransferOwnership);
}

/**
 *  RULE: Future address cant become None
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 *       
*/
#[rule]
pub fn future_address_cant_become_none_access_control(e: Env) {
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

#[rule]
fn TEST_TRANSFER_2(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let value = nondet();
    acc_ctrl.put_transfer_ownership_deadline(&role, value);
    cvlr_satisfy!(true);
}

/**
 *  RULE: Deadline changed to nonzero => commit or put_transfer_deadline called
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 *       
*/
#[rule]
pub fn deadline_changed_to_nonzero_commit_or_put_transfer_deadline(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    let action = nondet_func(e.clone());

    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assume!(deadline_before != deadline_after && deadline_after > 0);

    cvlr_assert!(
        action == Action::CommitTransferOwnership || action == Action::PutTransferOwnershipDeadline
    );
}

/**
 *  RULE: Deadline changed to zero => revert, apply or put_transfer_deadline
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn deadline_changed_to_zero_revert_apply_or_put_transfer_deadline(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    let action = nondet_func(e.clone());

    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assume!(deadline_before != deadline_after && deadline_after == 0);

    cvlr_assert!(
        action == Action::ApplyTransferOwnership
            || action == Action::PutTransferOwnershipDeadline
            || action == Action::RevertTransferOwnership
    );
}

/**
 *  RULE: Deadline can only change to > now() or zero
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 *       
*/
#[rule]
pub fn deadline_valid_states_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    let action = nondet_func(e.clone());

    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assume!(deadline_before != deadline_after);

    cvlr_assert!(
        deadline_after == 0
            || deadline_after > e.ledger().timestamp()
            || action == Action::PutTransferOwnershipDeadline
    );
}

/**
 *  RULE: Deadline != 0 => commit reverts
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 *       
*/
#[rule]
pub fn cant_commit_if_deadline_nonzero() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let deadline = acc_ctrl.get_transfer_ownership_deadline(&role);
    cvlr_assume!(deadline != 0);

    acc_ctrl.commit_transfer_ownership(&role, &nondet_address());

    cvlr_assert!(false); // shoudlnt reach
}

/**
 *  RULE: Now() < deadline or role address isnt none => apply reverts
 *  Tested: Yes
 *  Bugs: No
 *  Note: 
*/
#[rule]
pub fn cant_apply_before_deadline(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let deadline = acc_ctrl.get_transfer_ownership_deadline(&role);
    cvlr_assume!(
        e.ledger().timestamp() < deadline && acc_ctrl.get_role_safe(&role).is_some()
    );
    role_to_string(&role);
    clog!(e.ledger().timestamp());
    clog!(deadline);

    let address = acc_ctrl.apply_transfer_ownership(&role);
    clog!(cvlr_soroban::Addr(&address));

    cvlr_assert!(false); // shoudlnt reach
}

/**
 *  RULE: Role address changed => new address == future address
 *  Tested: Yes
 *  Bugs: No
 *  Note:  not applicable for roles.has_many_users()
*/
#[rule]
pub fn role_changed_future_address_is_new_address(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let address_before = acc_ctrl.get_role_safe(&role);
    let future_add = acc_ctrl.get_future_address(&role);

    let action = nondet_func(e.clone());
    cvlr_assume!(action != Action::SetRoleAddress);

    let address_after = acc_ctrl.get_role_safe(&role);

    cvlr_assume!(address_before != address_after);

    match address_after {
        Some(address_after) => cvlr_assert!(address_after == future_add),
        None => cvlr_assert!(false) // shuldnt reach
        
    }
}

/**
 *  RULE: Role cant change to None
 *  Tested: Yes
 *  Bugs: No
 *  Note: The rule is not implemented for role.has_many_users()
 *        because there are no restrictions to those. The address vector can be empty.
*/
#[rule]
pub fn role_cant_change_to_none(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let address_before = acc_ctrl.get_role_safe(&role);

    nondet_func(e.clone());

    let address_after = acc_ctrl.get_role_safe(&role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!(address_after.is_some());
}

/**
 *  RULE: Role changed => role is either Admin or EmergencyAdmin unless using set_role_address
 *  Tested: Yes
 *  Bugs: No - but rule fails for Admin due to the from_symbol bug.
 *  Note: Theres also an option to change all roles via the set_role_address/es function.
 *        No need to check for has_many_users() because the rule is not applicable for those.
 *        
 */
#[rule]
pub fn role_changed_is_admin_or_emergency_admin(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();

    let address_before = acc_ctrl.get_role_safe(&role);
    role_to_string(&role);

    let action = nondet_func(e.clone());

    let address_after = acc_ctrl.get_role_safe(&role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!(
        action == Action::SetRoleAddress
            || role.as_symbol(&e) == Role::Admin.as_symbol(&e)
            || role.as_symbol(&e) == Role::EmergencyAdmin.as_symbol(&e)
    );
}

/**
 *  RULE: Role changed and has many users => set_role_addresses called
 *  Tested: Yes
 *  Bugs: Yes
 *  Note: (address_vec_before.len()>0 || address_vec_after.len()>0) added to the assumption due to the Vec comparison bug.
 */
#[rule]
pub fn role_has_many_users_changes_due_to_set_role_addresses(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);
    cvlr_assume!(role.has_many_users());

    let address_vec_before = acc_ctrl.get_role_addresses(&role);

    let action = nondet_func(e.clone());

    let address_vec_after = acc_ctrl.get_role_addresses(&role);

    cvlr_assume!((address_vec_before.len()>0 || address_vec_after.len()>0) && address_vec_before != address_vec_after);

    cvlr_assert!(action == Action::SetRoleAddresses);
}

/**
 *  RULE: Role.transfer_delay => !role.has_many_users
 *  Tested: Yes.  
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn role_has_transfer_delay_has_one_user() {
    let role = nondet_role();

    cvlr_assume!(role.is_transfer_delayed());
    cvlr_assert!(!role.has_many_users());
}

/**
 *  RULE: Role changed => apply was called or set_role_address
 *  Tested: Yes
 *  Bugs: No
 *  Note: The rule is not applicable for roles with many users. its covered by rule role_has_many_users_changes_due_to_set_role_addresses
*/
#[rule]
pub fn role_changed_due_to_apply_or_set_role(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let address_before = acc_ctrl.get_role_safe(&role);

    let action = nondet_func(e.clone());

    let address_after = acc_ctrl.get_role_safe(&role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!(action == Action::SetRoleAddress || action == Action::ApplyTransferOwnership)
}

/**
 *  RULE: Transfering a role doesnt affect the other roles even when the roles dont have many users
 *  Tested: Yes
 *  Bugs: No
 *  Note:
 */
#[rule]
pub fn one_role_at_a_time_both_not_has_many_access_control(e: Env) {
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

    cvlr_assert!(
        other_address_before == other_address_after
    );
}

/**
 *  RULE: Transfering a role doesnt affect the other roles even when only transfering role.has_many_users
 *  Tested: Yes
 *  Bugs: No
 *  Note: (addresses_before.len()>0 || addresses_after.len()>0) added to the assumption due to the Vec comparison bug.
 */
#[rule]
pub fn one_role_at_a_time_transfering_role_has_many_users_access_control(e: Env) {
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

    cvlr_assert!(
        other_address_before == other_address_after
    );
}

/**
 *  RULE: Transfering a role doesnt affect the other roles even when only other role.has_many_users
 *  Tested: Yes
 *  Bugs: No
 *  Note: other_addresses_before.len() == 0 && other_addresses_after.len() == 0 added to the assertion due to the Vec comparison bug.
 */
#[rule]
pub fn one_role_at_a_time_other_role_has_many_users_access_control(e: Env) {
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

    cvlr_assert!(
        (other_addresses_before == other_addresses_after) ||
        (other_addresses_before.len() == 0 && other_addresses_after.len() == 0)
    );
}

/**
 *  RULE: Transfering a role doesnt affect the other roles even when both role.has_many_users
 *  Tested: Yes
 *  Bugs: No
 *  Note: This rule should be vacuous because there is only one role that has many users. But it is
 *        included for completeness.
 *        other_addresses_before.len() == 0 && other_addresses_after.len() == 0 and added to the assertion due to the Vec comparison bug.
 *        (addresses_before.len()>0 || addresses_after.len()>0) added to the assumption due to the Vec comparison bug.
 */
#[rule]
pub fn one_role_at_a_time_both_has_many_users_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let other_role = nondet_role();
    role_to_string(&role);
    role_to_string(&other_role);   

    let addresses_before = acc_ctrl.get_role_addresses(&role);
    let other_addresses_before = acc_ctrl.get_role_addresses(&other_role);

    // Currently renders the rule vacuous.
    cvlr_assume!((addresses_before.len()>0 || other_addresses_before.len()>0) && addresses_before != other_addresses_before); 

    nondet_func(e.clone());

    let addresses_after = acc_ctrl.get_role_addresses(&role);
    let other_addresses_after = acc_ctrl.get_role_addresses(&other_role);

    cvlr_assume!((addresses_before.len()>0 || addresses_after.len()>0) && addresses_before != addresses_after);

    cvlr_assert!(
        (other_addresses_before == other_addresses_after) ||
        (other_addresses_before.len() == 0 && other_addresses_after.len() == 0)
    );
}


/**
 *  RULE: Admin can transfer his role
 *  Tested: Yes
 *  Bugs: No
 *  Note: Rule passes, however fails for fees_collector due to from_symbol bug.
*/
#[rule]
pub fn admin_can_transfer_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = Role::Admin;
    let address_before = acc_ctrl.get_role_safe(&role);

    nondet_func(e.clone());

    let address_after = acc_ctrl.get_role_safe(&role);

    cvlr_satisfy!(address_before != address_after);
}

/**
 *  RULE: Emergency Admin can transfer his role
 *  Tested: Yes
 *  Bugs: No
 *  Note: redundant, but included for completeness.
*/
#[rule]
pub fn emergency_admin_can_transfer_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = Role::EmergencyAdmin;
    let address_before = acc_ctrl.get_role_safe(&role);

    nondet_func(e.clone());

    let address_after = acc_ctrl.get_role_safe(&role);

    cvlr_satisfy!(address_before != address_after);
}

/**
 *  RULE: if revert called => apply reverts
 *  Tested: Yes  
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn cant_apply_transfer_if_revert_called_access_control() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();

    acc_ctrl.revert_transfer_ownership(&role);
    acc_ctrl.apply_transfer_ownership(&role);

    cvlr_assert!(false); // shouldnt reach
}

/**
 * UNIT TESTS
 */

/**
 *  RULE: address_has_role integrity
 *  Tested: No
 *  Bugs: Yes
 *  Note:   Doesnt work for roles with many users because the .contains method for vectors
 *          in soroban sdk is not implemented. As per https://discord.com/channels/795999272293236746/1375030757013192795
*/
#[rule]
pub fn address_has_role_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    let address = nondet_address();
    clog!(role.has_many_users());
    role_to_string(&role);

    if role.has_many_users() {
        cvlr_assume!(e.storage().instance().get(&role_key).unwrap_or(Vec::<Address>::new(&e)).contains(&address));
        cvlr_assert!(acc_ctrl.address_has_role(&address, &role));
    } else {
        cvlr_assume!(address == e.storage().instance().get(&role_key).unwrap());
        cvlr_assert!(acc_ctrl.address_has_role(&address, &role));
    }
}

/**
 *  RULE: get_role_safe integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn get_role_safe_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    role_to_string(&role);

    let address = acc_ctrl.get_role_safe(&role);

    cvlr_assert!(address == e.storage().instance().get(&role_key));
}

/**
 *  RULE: get_role integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn get_role_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let address = acc_ctrl.get_role(&role);
    clog!(cvlr_soroban::Addr(&address));    
    role_to_string(&role);

    let role_key = acc_ctrl.get_key(&role);

    match e.storage().instance().get::<DataKey, Address>(&role_key) {
        Some(add) => cvlr_assert!(address == add),
        None => cvlr_assert!(false), // shouldnt reach here.
    }
}

/**
 *  RULE: set_role_address integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:   Can be used to set any role.
 *          If role is not set yet, it doesnt matter which role it is (excluding has_many_users)
 *          If role is set, then we cant use this function if is_transfer_delayed
*/
#[rule]
pub fn set_role_address_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    let address_before = acc_ctrl.get_role_safe(&role);
    let address_to_set = nondet_address();

    acc_ctrl.set_role_address(&role, &address_to_set);

    let address_after = e.storage().instance().get::<DataKey, Address>(&role_key);

    match address_after{
        Some(address_after) => cvlr_assert!(
                !role.has_many_users()
            && address_after == address_to_set
            && ((address_before.is_some() && !role.is_transfer_delayed()) || (address_before.is_none()))
        ),
        None => {
            cvlr_assert!(false); // Cant set address to None
        }
    }
}

/**
 *  RULE: get_role_addresses integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note: (get_value.len() == 0 && true_value.len() == 0 ) was added to the assertion due to the Vec comparison bug.  
 */
#[rule]
pub fn get_role_addresses_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    role_to_string(&role);

    let get_value = acc_ctrl.get_role_addresses(&role);

    let true_value = e.storage().instance().get::<DataKey, Vec<Address>>(&role_key).unwrap_or(Vec::new(&e));

    cvlr_assert!(role.has_many_users() && (get_value == true_value || (get_value.len() == 0 && true_value.len() == 0 )));
}

/**
 *  RULE: set_role_addresses integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn set_role_addresses_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let role_key: DataKey = acc_ctrl.get_key(&role);
    let addresses_to_set = nondet_vec::<Address>();

    acc_ctrl.set_role_addresses(&role, &addresses_to_set);

    let true_address = e.storage().instance().get::<DataKey, Vec<Address>>(&role_key).unwrap_or(Vec::new(&e));
    cvlr_assert!(role.has_many_users() && addresses_to_set == true_address);
}

/**
 *  RULE: get_emergency_mode integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn get_emergency_mode_integrity_access_control(e: Env) {
    let value: bool = access_control::emergency::get_emergency_mode(&e);
    let emergency_mode_key = DataKey::EmergencyMode;
    cvlr_assert!(
        e.storage().instance().get::<DataKey, bool>(&emergency_mode_key).unwrap() == value
    );
}

/**
 *  RULE: require_rewards_admin_or_owner integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn require_rewards_admin_or_owner_integrity(e: Env) {
    let address: Address = nondet_address();

    access_control::utils::require_rewards_admin_or_owner(&e, &address);

    cvlr_assert!(is_role(&address, &Role::Admin) || is_role(&address, &Role::RewardsAdmin));
}

/**
 *  RULE: require_operations_admin_or_owner integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn require_operations_admin_or_owner_integrity(e: Env) {
    let address = nondet_address();

    access_control::utils::require_operations_admin_or_owner(&e, &address);

    cvlr_assert!(is_role(&address, &Role::Admin) || is_role(&address, &Role::OperationsAdmin));
}

/**
 *  RULE: require_pause_or_emergency_pause_admin_or_owner integrity
 *  Tested: Yes
 *  Bugs: Yes
 *  Note: FAILS for emergency pause admin due to issue with Vec<Address>.contain bug
 *          as per: https://discord.com/channels/795999272293236746/1375030757013192795
*/
#[rule]
pub fn require_pause_or_emergency_pause_admin_or_owner_integrity(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));

    access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);

    clog!(is_role(&address, &Role::EmergencyPauseAdmin));
    clog!(is_role(&address, &Role::PauseAdmin));
    clog!(is_role(&address, &Role::Admin));

    let true_pause_admin = e.storage().instance().get::<DataKey, Address>(&DataKey::PauseAdmin).unwrap();
    let true_emergency_pause_admin = e.storage().instance().get::<DataKey, Vec<Address>>(&DataKey::EmPauseAdmins).unwrap_or(Vec::new(&e));
    let true_admin = e.storage().instance().get::<DataKey, Address>(&DataKey::Admin).unwrap();

    let is_emergency_admin = true_emergency_pause_admin.contains(&address); //buggy

    cvlr_assert!(address == true_admin || address == true_pause_admin || is_emergency_admin);
}

/**
 *  RULE: require_pause_admin_or_owner integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn require_pause_admin_or_owner_integrity(e: Env) {
    let address = nondet_address();

    access_control::utils::require_pause_admin_or_owner(&e, &address);

    cvlr_assert!(is_role(&address, &Role::Admin) || is_role(&address, &Role::PauseAdmin));
}

/**
 *  RULE: assert_address_has_role_integrity
 *  Tested: Yes
 *  Bugs: Yes
 *  Note:   Doesnt work for roles with many users because the vec.contains bug
 *          As per https://discord.com/channels/795999272293236746/1375030757013192795
*/
#[rule]
pub fn assert_address_has_role_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let address = nondet_address();
    let role = nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    clog!(role.has_many_users());
    acc_ctrl.assert_address_has_role(&address, &role);

    cvlr_assert!(
        (!role.has_many_users()
            && address == e.storage().instance().get::<DataKey, Address>(&role_key).unwrap())
            || (role.has_many_users()
                && e.storage().instance().get::<DataKey, Vec<Address>>(&role_key).unwrap_or(Vec::new(&e)).contains(&address))
    );
}

/**
 *  RULE: Commit_transfer_ownership integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn commit_transfer_ownership_integrity_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let future_address = nondet_address();
    let role = nondet_role();
    let future_role_key = acc_ctrl.get_future_key(&role);

    acc_ctrl.commit_transfer_ownership(&role, &future_address);

    let commited_address = e.storage().instance().get::<DataKey, Address>(&future_role_key);
    
    match commited_address {
        Some(commited_address) => cvlr_assert!(
            commited_address == future_address
            && get_transfer_deadline(&role) == e.ledger().timestamp() + access_control::constants::ADMIN_ACTIONS_DELAY
            && role.is_transfer_delayed()
            && !role.has_many_users()
        ),
        None => cvlr_assert!(false), // shouldnt reach
    }
}

/**
 *  RULE: apply_transfer_ownership integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn apply_transfer_ownership_integrity_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let current_address = acc_ctrl.get_role_safe(&role);
    let future_address = acc_ctrl.get_future_address(&role);
    let role_key = acc_ctrl.get_future_key(&role);
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    let returned_address = acc_ctrl.apply_transfer_ownership(&role);

    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    let true_address = e.storage().instance().get::<DataKey, Address>(&role_key);

    match true_address {
        Some(true_address) => cvlr_assert!(
            returned_address == true_address
            && future_address == true_address
            && deadline_after == 0
            && ((current_address.is_some() && deadline_before <= e.ledger().timestamp())
                || (current_address.is_none()))
        ),
        None => cvlr_assert!(false), // Cant transfer to None
    }

}

/**
 *  RULE: revert_transfer_ownership integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn revert_transfer_ownership_integrity_access_control() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    role_to_string(&role);

    acc_ctrl.revert_transfer_ownership(&role);

    cvlr_assert!(acc_ctrl.get_transfer_ownership_deadline(&role) == 0);
}

/**
 *  RULE: get_future_address integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn get_future_address_integrity_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let future_role_key = acc_ctrl.get_future_key(&role);

    cvlr_assert!(
        acc_ctrl.get_future_address(&role) == e.storage().instance().get::<DataKey, Address>(&future_role_key).unwrap()
    );
}

/**
 *  RULE: put_transfer_ownership_deadline integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn put_transfer_ownership_deadline_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let deadline_key = acc_ctrl.get_future_deadline_key(&role);
    let value = nondet();
    role_to_string(&role);
    acc_ctrl.put_transfer_ownership_deadline(&role, value);

    cvlr_assert!(
        value == e.storage().instance().get::<DataKey, u64>(&deadline_key).unwrap()
    );
}

/**
 *  RULE: get_transfer_ownership_deadline integrity
 *  Tested: Yes
 *  Bugs: No
 *  Note:
*/
#[rule]
pub fn get_transfer_ownership_deadline_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let deadline_key = acc_ctrl.get_future_deadline_key(&role);
    role_to_string(&role);

    let get_deadline = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assert!(
        get_deadline == e.storage().instance().get::<DataKey, u64>(&deadline_key).unwrap()
    );
}