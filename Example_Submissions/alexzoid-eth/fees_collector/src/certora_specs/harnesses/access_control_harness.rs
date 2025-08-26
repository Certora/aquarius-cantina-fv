// This extends FeesCollector with harness functions from access_control

use soroban_sdk::{contractimpl, Address, Env, Symbol, Vec};
use crate::contract::{FeesCollector, FeesCollectorArgs};
use crate::FeesCollectorClient;
use access_control::{
    access::{AccessControl, AccessControlTrait},
    emergency::{get_emergency_mode, set_emergency_mode},
    management::{SingleAddressManagementTrait, MultipleAddressesManagementTrait},
    role::{Role, SymbolRepresentation},
    storage::{DataKey, StorageTrait},
    transfer::TransferOwnershipTrait,
    utils::*,
};

#[contractimpl]
impl FeesCollector {

    pub fn h_init_all_roles(
        e: Env,
        admin: Address,
        emergency_admin: Address,
        rewards_admin: Address,
        operations_admin: Address,
        pause_admin: Address,
        emergency_pause_admins: Vec<Address>,
    ) {
        let access_control = AccessControl::new(&e);
        
        access_control.set_role_address(&Role::Admin, &admin);
        access_control.set_role_address(&Role::EmergencyAdmin, &emergency_admin);
        access_control.set_role_address(&Role::RewardsAdmin, &rewards_admin);
        access_control.set_role_address(&Role::OperationsAdmin, &operations_admin);
        access_control.set_role_address(&Role::PauseAdmin, &pause_admin);
        
        access_control.set_role_addresses(&Role::EmergencyPauseAdmin, &emergency_pause_admins);
    }

    pub fn h_get_role_safe(e: Env, role_name: Symbol) -> Option<Address> {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.get_role_safe(&role)
    }

    pub fn h_get_role(e: Env, role_name: Symbol) -> Address {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.get_role(&role)
    }

    pub fn h_set_role_address(e: Env, role_name: Symbol, address: Address) {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.set_role_address(&role, &address);
    }

    pub fn h_get_role_addresses(e: Env, role_name: Symbol) -> Vec<Address> {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.get_role_addresses(&role)
    }

    pub fn h_set_role_addresses(e: Env, role_name: Symbol, addresses: Vec<Address>) {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.set_role_addresses(&role, &addresses);
    }

    pub fn h_address_has_role(e: Env, address: Address, role_name: Symbol) -> bool {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.address_has_role(&address, &role)
    }

    pub fn h_assert_address_has_role(e: Env, address: Address, role_name: Symbol) {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.assert_address_has_role(&address, &role);
    }

    pub fn h_commit_transfer_ownership(e: Env, role_name: Symbol, future_address: Address) {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.commit_transfer_ownership(&role, &future_address);
    }

    pub fn h_apply_transfer_ownership(e: Env, role_name: Symbol) -> Address {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.apply_transfer_ownership(&role)
    }

    pub fn h_revert_transfer_ownership(e: Env, role_name: Symbol) {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.revert_transfer_ownership(&role);
    }

    pub fn h_get_transfer_ownership_dl(e: Env, role_name: Symbol) -> u64 {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.get_transfer_ownership_deadline(&role)
    }

    pub fn h_get_future_address(e: Env, role_name: Symbol) -> Address {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.get_future_address(&role)
    }

    pub fn h_require_rewards_admin_or_owner(e: Env, address: Address) {
        require_rewards_admin_or_owner(&e, &address);
    }

    pub fn h_require_operations_admin_owner(e: Env, address: Address) {
        require_operations_admin_or_owner(&e, &address);
    }

    pub fn h_require_pause_emergency_admin(e: Env, address: Address) {
        require_pause_or_emergency_pause_admin_or_owner(&e, &address);
    }

    pub fn h_require_pause_admin_or_owner(e: Env, address: Address) {
        require_pause_admin_or_owner(&e, &address);
    }

    pub fn h_set_emergency_mode_direct(e: Env, value: bool) {
        set_emergency_mode(&e, &value);
    }

    pub fn h_get_emergency_mode_direct(e: Env) -> bool {
        get_emergency_mode(&e)
    }

    pub fn h_role_has_many_users(e: Env, role_name: Symbol) -> bool {
        let role = Role::from_symbol(&e, role_name);
        role.has_many_users()
    }

    pub fn h_role_is_transfer_delayed(e: Env, role_name: Symbol) -> bool {
        let role = Role::from_symbol(&e, role_name);
        role.is_transfer_delayed()
    }

    pub fn h_set_privileged_addrs(
        e: Env,
        rewards_admin: Address,
        operations_admin: Address,
        pause_admin: Address,
        emergency_pause_admins: Vec<Address>,
    ) {
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&Role::RewardsAdmin, &rewards_admin);
        access_control.set_role_address(&Role::OperationsAdmin, &operations_admin);
        access_control.set_role_address(&Role::PauseAdmin, &pause_admin);
        access_control.set_role_addresses(&Role::EmergencyPauseAdmin, &emergency_pause_admins);
    }

    pub fn h_get_storage_key(e: Env, role_name: Symbol) -> u32 {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        let key = access_control.get_key(&role);
        // Return a numeric representation of the DataKey for testing
        match key {
            DataKey::Admin => 1,
            DataKey::EmergencyAdmin => 2,
            DataKey::Operator => 3,
            DataKey::OperationsAdmin => 4,
            DataKey::PauseAdmin => 5,
            DataKey::EmPauseAdmins => 6,
            DataKey::FutureAdmin => 7,
            DataKey::FutureEmergencyAdmin => 8,
            DataKey::TransferOwnershipDeadline => 9,
            DataKey::EmAdminTransferOwnershipDeadline => 10,
            DataKey::EmergencyMode => 11,
        }
    }

    pub fn h_get_future_storage_key(e: Env, role_name: Symbol) -> u32 {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        let key = access_control.get_future_key(&role);
        // Return a numeric representation of the DataKey for testing
        match key {
            DataKey::Admin => 1,
            DataKey::EmergencyAdmin => 2,
            DataKey::Operator => 3,
            DataKey::OperationsAdmin => 4,
            DataKey::PauseAdmin => 5,
            DataKey::EmPauseAdmins => 6,
            DataKey::FutureAdmin => 7,
            DataKey::FutureEmergencyAdmin => 8,
            DataKey::TransferOwnershipDeadline => 9,
            DataKey::EmAdminTransferOwnershipDeadline => 10,
            DataKey::EmergencyMode => 11,
        }
    }

    pub fn h_get_future_deadline_key(e: Env, role_name: Symbol) -> u32 {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        let key = access_control.get_future_deadline_key(&role);
        // Return a numeric representation of the DataKey for testing
        match key {
            DataKey::Admin => 1,
            DataKey::EmergencyAdmin => 2,
            DataKey::Operator => 3,
            DataKey::OperationsAdmin => 4,
            DataKey::PauseAdmin => 5,
            DataKey::EmPauseAdmins => 6,
            DataKey::FutureAdmin => 7,
            DataKey::FutureEmergencyAdmin => 8,
            DataKey::TransferOwnershipDeadline => 9,
            DataKey::EmAdminTransferOwnershipDeadline => 10,
            DataKey::EmergencyMode => 11,
        }
    }
    
    // Role ID constants
    pub const ROLE_ID_ADMIN: u32 = 1;
    pub const ROLE_ID_EMERGENCY_ADMIN: u32 = 2;
    pub const ROLE_ID_REWARDS_ADMIN: u32 = 3;
    pub const ROLE_ID_OPERATIONS_ADMIN: u32 = 4;
    pub const ROLE_ID_PAUSE_ADMIN: u32 = 5;
    pub const ROLE_ID_EMERGENCY_PAUSE_ADMIN: u32 = 6;

    fn role_from_id(role_id: u32) -> Role {
        match role_id {
            1 => Role::Admin,
            2 => Role::EmergencyAdmin,
            3 => Role::RewardsAdmin,
            4 => Role::OperationsAdmin,
            5 => Role::PauseAdmin,
            6 => Role::EmergencyPauseAdmin,
            _ => panic!("Invalid role ID"),
        }
    }

    pub fn role_id_to_symbol(e: Env, role_id: u32) -> Symbol {
        let role = Self::role_from_id(role_id);
        role.as_symbol(&e)
    }

    pub fn h_get_role_by_id(e: Env, role_id: u32) -> Address {
        let access_control = AccessControl::new(&e);
        let role = Self::role_from_id(role_id);
        access_control.get_role(&role)
    }

    pub fn h_get_role_safe_by_id(e: Env, role_id: u32) -> Option<Address> {
        let access_control = AccessControl::new(&e);
        let role = Self::role_from_id(role_id);
        access_control.get_role_safe(&role)
    }

    pub fn h_set_role_address_by_id(e: Env, role_id: u32, address: Address) {
        let access_control = AccessControl::new(&e);
        let role = Self::role_from_id(role_id);
        access_control.set_role_address(&role, &address);
    }

    pub fn h_get_storage_key_by_id(e: Env, role_id: u32) -> u32 {
        let access_control = AccessControl::new(&e);
        let role = Self::role_from_id(role_id);
        let key = access_control.get_key(&role);
        match key {
            DataKey::Admin => 1,
            DataKey::EmergencyAdmin => 2,
            DataKey::Operator => 3,
            DataKey::OperationsAdmin => 4,
            DataKey::PauseAdmin => 5,
            DataKey::EmPauseAdmins => 6,
            DataKey::FutureAdmin => 7,
            DataKey::FutureEmergencyAdmin => 8,
            DataKey::TransferOwnershipDeadline => 9,
            DataKey::EmAdminTransferOwnershipDeadline => 10,
            DataKey::EmergencyMode => 11,
        }
    }

    pub fn h_get_future_storage_key_by_id(e: Env, role_id: u32) -> u32 {
        let access_control = AccessControl::new(&e);
        let role = Self::role_from_id(role_id);
        let key = access_control.get_future_key(&role);
        match key {
            DataKey::Admin => 1,
            DataKey::EmergencyAdmin => 2,
            DataKey::Operator => 3,
            DataKey::OperationsAdmin => 4,
            DataKey::PauseAdmin => 5,
            DataKey::EmPauseAdmins => 6,
            DataKey::FutureAdmin => 7,
            DataKey::FutureEmergencyAdmin => 8,
            DataKey::TransferOwnershipDeadline => 9,
            DataKey::EmAdminTransferOwnershipDeadline => 10,
            DataKey::EmergencyMode => 11,
        }
    }

    pub fn h_get_future_deadline_key_by_id(e: Env, role_id: u32) -> u32 {
        let access_control = AccessControl::new(&e);
        let role = Self::role_from_id(role_id);
        let key = access_control.get_future_deadline_key(&role);
        match key {
            DataKey::Admin => 1,
            DataKey::EmergencyAdmin => 2,
            DataKey::Operator => 3,
            DataKey::OperationsAdmin => 4,
            DataKey::PauseAdmin => 5,
            DataKey::EmPauseAdmins => 6,
            DataKey::FutureAdmin => 7,
            DataKey::FutureEmergencyAdmin => 8,
            DataKey::TransferOwnershipDeadline => 9,
            DataKey::EmAdminTransferOwnershipDeadline => 10,
            DataKey::EmergencyMode => 11,
        }
    }

    // Direct role access functions
    pub fn h_get_admin_role(e: Env) -> Address {
        let access_control = AccessControl::new(&e);
        access_control.get_role(&Role::Admin)
    }

    pub fn h_get_emergency_admin_safe(e: Env) -> Option<Address> {
        let access_control = AccessControl::new(&e);
        access_control.get_role_safe(&Role::EmergencyAdmin)
    }

    pub fn h_get_rewards_admin_safe(e: Env) -> Option<Address> {
        let access_control = AccessControl::new(&e);
        access_control.get_role_safe(&Role::RewardsAdmin)
    }

    pub fn h_get_operations_admin_safe(e: Env) -> Option<Address> {
        let access_control = AccessControl::new(&e);
        access_control.get_role_safe(&Role::OperationsAdmin)
    }

    pub fn h_get_pause_admin_safe(e: Env) -> Option<Address> {
        let access_control = AccessControl::new(&e);
        access_control.get_role_safe(&Role::PauseAdmin)
    }

    pub fn h_set_admin_address(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&Role::Admin, &address);
    }

    pub fn h_set_emergency_admin_address(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&Role::EmergencyAdmin, &address);
    }

    pub fn h_set_rewards_admin_address(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&Role::RewardsAdmin, &address);
    }

    pub fn h_set_operations_admin_address(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&Role::OperationsAdmin, &address);
    }

    pub fn h_set_pause_admin_address(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&Role::PauseAdmin, &address);
    }

    pub fn h_get_role_addresses_by_id(e: Env, role_id: u32) -> Vec<Address> {
        let access_control = AccessControl::new(&e);
        let role = Self::role_from_id(role_id);
        access_control.get_role_addresses(&role)
    }

    pub fn h_set_role_addresses_by_id(e: Env, role_id: u32, addresses: Vec<Address>) {
        let access_control = AccessControl::new(&e);
        let role = Self::role_from_id(role_id);
        access_control.set_role_addresses(&role, &addresses);
    }
}