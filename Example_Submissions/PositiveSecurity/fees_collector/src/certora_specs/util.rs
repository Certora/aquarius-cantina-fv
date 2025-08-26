use soroban_sdk::Address;

use access_control::management::SingleAddressManagementTrait;
use access_control::access::AccessControlTrait;
use access_control::role::Role;
use access_control::transfer::TransferOwnershipTrait;
use access_control::storage::{DataKey, StorageTrait};

use crate::certora_specs::ACCESS_CONTROL;

pub fn get_role_address() -> Address {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    return acc_ctrl.as_ref().unwrap().get_role(&Role::Admin);
}

pub fn is_role(address: &Address, role: &Role) -> bool {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    return acc_ctrl.as_ref().unwrap().address_has_role(&address, role)
}

pub fn get_deadline(role: &Role) -> u64 {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    return acc_ctrl.as_ref().unwrap().get_transfer_ownership_deadline(role);
}

pub fn get_key(role: &Role) -> DataKey {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    return acc_ctrl.as_ref().unwrap().get_key(role);
}

pub fn get_future_address(role: &Role) -> Address {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    return acc_ctrl.as_ref().unwrap().get_future_address(role);
}
