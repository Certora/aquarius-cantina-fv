
use access_control::transfer::TransferOwnershipTrait;
use cvlr::clog;
// use cvlr::cvlr_assert;
use cvlr::nondet;
// use cvlr_soroban::is_auth;
use cvlr_soroban::nondet_address;
use soroban_sdk::BytesN;
use soroban_sdk::Env;

use access_control::role::Role;
use crate::FeesCollector;
use cvlr::nondet::Nondet;
use crate::certora_specs::ACCESS_CONTROL;
// use super::util::get_role_safe_address;

pub fn get_transfer_deadline(role: &Role) -> u64{
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    acc_ctrl.as_ref().unwrap().get_transfer_ownership_deadline(role)
}


pub mod fees_collector_funcs{
    use super::FeesCollector;
    use super::{Env,nondet_address, nondet_role, nondet_wasm,Nondet};
    use upgrade::interface::UpgradeableContract;
    use crate::interface::AdminInterface;
    use access_control::interface::TransferableContract;
    use access_control::role::SymbolRepresentation;

    // Creating a Paramatric function nondet() without upgrade
    #[derive(Debug, PartialEq, Eq)]
    pub enum Action{
        InitAdmin,
        SetEmergencyMode,
        GetEmergencyMode,
        CommitTransfer,
        ApplyTransfer,
        RevertTransfer,
        GetFutureAddress,
        Version,
        CommitUpgrade,
        ApplyUpgrade,
        RevertUpgrade
    }
    
    pub fn nondet_func(e: Env) -> Action{
        // It seems that using modulu is actually slower then 
        // Allowing the prover to determin the numbers itself.
        //let action: Action = match u8::nondet() % 7{
            let action: Action = match u8::nondet_with(|val| val<&11){
                0 => Action::InitAdmin,
                1 => Action::SetEmergencyMode,
                2 => Action::GetEmergencyMode,
                3 => Action::CommitTransfer,
                4 => Action::ApplyTransfer,
                5 => Action::RevertTransfer,
                6 => Action::GetFutureAddress,
                7 => Action::Version,
                8 => Action::CommitUpgrade,
                9 => Action::ApplyUpgrade,
                10 => Action::RevertUpgrade,
                _ => panic!("Error with nondet func")
            };
            
            //let action = Action::CommitTransfer;
            match action{
                Action::InitAdmin => FeesCollector::init_admin(e.clone(), nondet_address()),
                Action::SetEmergencyMode => FeesCollector::set_emergency_mode(e.clone(), nondet_address(), bool::nondet()),
                Action::GetEmergencyMode => match FeesCollector::get_emergency_mode(e.clone()){true => (), false => ()},
                Action::CommitTransfer => FeesCollector::commit_transfer_ownership(e.clone(), nondet_address(), nondet_role().as_symbol(&e), nondet_address()),
                Action::ApplyTransfer => FeesCollector::apply_transfer_ownership(e.clone(), nondet_address(), nondet_role().as_symbol(&e)),
                Action::RevertTransfer => FeesCollector::revert_transfer_ownership(e.clone(), nondet_address(), nondet_role().as_symbol(&e)),
                Action::GetFutureAddress => match FeesCollector::get_future_address(e.clone(), nondet_role().as_symbol(&e)) {_add => ()},
                Action::Version => match FeesCollector::version() {_v => ()},
                Action::CommitUpgrade => FeesCollector::commit_upgrade(e.clone(), nondet_address(), nondet_wasm()),
                Action::ApplyUpgrade => match FeesCollector::apply_upgrade(e.clone(), nondet_address()){_v => ()},
                Action::RevertUpgrade => FeesCollector::revert_upgrade(e.clone(), nondet_address()),
            }
            return action;
        }
}

/**
 * Asaf
 * In order to produce a nondet hash, of 256bits, without caling nondet() 32 times,
 * which causes a 'problem', naturally,
 * we create two nondets of the biggest size implemented and break them into bytes,
 * then turn them into BytesN.
 * 
*/ 
pub fn nondet_wasm() -> BytesN<32> {
    let first_u128 = nondet::<u128>();
    let second_u128 = nondet::<u128>();
    let bytes_chunk1 = first_u128.to_be_bytes();
    let bytes_chunk2 = second_u128.to_be_bytes();

    let mut full_bytes_array = [0u8; 32];
    full_bytes_array[0..16].copy_from_slice(&bytes_chunk1);
    full_bytes_array[16..32].copy_from_slice(&bytes_chunk2);

    BytesN::from_array(&Env::default(), &full_bytes_array)
}

// Creating a Role nondet()
pub fn nondet_role() -> Role {
    let role = match u8::nondet_with(|val| val<&6 ){
    //match u8::nondet() % 6{
        0 => Role::Admin,
        1 => Role::EmergencyAdmin,
        2 => Role::EmergencyPauseAdmin,
        3 => Role::OperationsAdmin,
        4 => Role::PauseAdmin,
        5 => Role::RewardsAdmin,
        _ => panic!("Error with nondet role")
    };

    return role;
}

// Access Control Nonedet Funcs
pub mod access_control_funcs{
    use super::ACCESS_CONTROL;
    use super::{Env,nondet_address, nondet_role };
    use access_control::access::AccessControlTrait;
    use access_control::management::{MultipleAddressesManagementTrait, SingleAddressManagementTrait};
    use access_control::transfer::TransferOwnershipTrait;
    use cvlr::nondet::{ nondet_with,nondet};
    use cvlr_soroban::nondet_vec;
    use access_control::storage::StorageTrait;
    // use soroban_sdk::Address;
    // use upgrade::interface::UpgradeableContract;
    // use crate::interface::AdminInterface;
    // use access_control::interface::TransferableContract;
    // use access_control::role::SymbolRepresentation;

    // Creating a Paramatric function nondet() without upgrade
    #[derive(Debug, PartialEq, Eq)]
    pub enum Action {
        // From mod access::AccessControl
        AddressHasRole,
        ApplyTransferOwnership,
        AssertAddressHasRole,
        CommitTransferOwnership,
        GetFutureAddress,
        GetFutureDeadlineKey,
        GetFutureKey,
        GetKey,
        GetRole,
        GetRoleAddresses,
        GetRoleSafe,
        GetTransferOwnershipDeadline,
        NewAccessControl, // Renamed 'new' to avoid conflict and clarify context
        PutTransferOwnershipDeadline,
        RevertTransferOwnership,
        SetRoleAddress,
        SetRoleAddresses,

        // From mod emergency
        GetEmergencyMode,
        SetEmergencyMode,

        // From mod utils
        RequireOperationsAdminOrOwner,
        RequirePauseAdminOrOwner,
        RequirePauseOrEmergencyPauseAdminOrOwner,
        RequireRewardsAdminOrOwner,
    }
    
    pub fn nondet_func(e: Env) -> Action{

        let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };

        let action: Action = match nondet_with(|val: &u8| val < &23) { 
            0 => Action::AddressHasRole,
            1 => Action::ApplyTransferOwnership,
            2 => Action::AssertAddressHasRole,
            3 => Action::CommitTransferOwnership,
            4 => Action::GetFutureAddress,
            5 => Action::GetFutureDeadlineKey,
            6 => Action::GetFutureKey,
            7 => Action::GetKey,
            8 => Action::GetRole,
            9 => Action::GetRoleAddresses,
            10 => Action::GetRoleSafe,
            11 => Action::GetTransferOwnershipDeadline,
            12 => Action::PutTransferOwnershipDeadline,
            13 => Action::RevertTransferOwnership,
            14 => Action::SetRoleAddress,
            15 => Action::SetRoleAddresses,
            16 => Action::GetEmergencyMode,
            17 => Action::SetEmergencyMode,
            18 => Action::RequireOperationsAdminOrOwner,
            19 => Action::RequirePauseAdminOrOwner,
            20 => Action::RequirePauseOrEmergencyPauseAdminOrOwner,
            21 => Action::RequireRewardsAdminOrOwner,
            22 => Action::NewAccessControl, 
            _ => panic!("Non-deterministic value out of expected range for Action enum. This should not happen with proper constraints."),
        };
            
            //let action = Action::CommitTransfer;
        match action{
            Action::AddressHasRole                  => match acc_ctrl.as_ref().unwrap().address_has_role(&nondet_address(), &nondet_role()){_=>()},
            Action::ApplyTransferOwnership          => match acc_ctrl.as_ref().unwrap().apply_transfer_ownership(&nondet_role()){_=>()},
            Action::AssertAddressHasRole            => match acc_ctrl.as_ref().unwrap().assert_address_has_role(&nondet_address(), &nondet_role()){_=>()}, 
            Action::CommitTransferOwnership         => match acc_ctrl.as_ref().unwrap().commit_transfer_ownership(&nondet_role(), &nondet_address()){_=>()},
            Action::GetFutureAddress                => match acc_ctrl.as_ref().unwrap().get_future_address(&nondet_role()){_=>()},
            Action::GetFutureDeadlineKey            => match acc_ctrl.as_ref().unwrap().get_future_deadline_key(&nondet_role()){_=>()}, 
            Action::GetFutureKey                    => match acc_ctrl.as_ref().unwrap().get_future_key(&nondet_role()){_=>()},
            Action::GetKey                          => match acc_ctrl.as_ref().unwrap().get_key(&nondet_role()){_=>()},
            Action::GetRole                         => match acc_ctrl.as_ref().unwrap().get_role(&nondet_role()){_=>()},
            Action::GetRoleAddresses                => match acc_ctrl.as_ref().unwrap().get_role_addresses(&nondet_role()){_=>()},
            Action::GetRoleSafe                     => match acc_ctrl.as_ref().unwrap().get_role_safe(&nondet_role()){_=>()},
            Action::GetTransferOwnershipDeadline    => match acc_ctrl.as_ref().unwrap().get_transfer_ownership_deadline(&nondet_role()){_=>()},
            Action::PutTransferOwnershipDeadline    => match acc_ctrl.as_ref().unwrap().put_transfer_ownership_deadline(&nondet_role(), nondet()){_=>()},
            Action::RevertTransferOwnership         => match acc_ctrl.as_ref().unwrap().revert_transfer_ownership(&nondet_role()){_=>()},
            Action::SetRoleAddress                  => match acc_ctrl.as_ref().unwrap().set_role_address(&nondet_role(), &nondet_address()){_=>()},
            Action::SetRoleAddresses                => match acc_ctrl.as_ref().unwrap().set_role_addresses(&nondet_role(), &nondet_vec()){_=>()},
            Action::GetEmergencyMode                => match access_control::emergency::get_emergency_mode(&e) {_=>()},
            Action::SetEmergencyMode                => match access_control::emergency::set_emergency_mode(&e, &nondet()){_=>()},
            Action::RequireOperationsAdminOrOwner   => match access_control::utils::require_operations_admin_or_owner(&e, &nondet_address()){_=>()},
            Action::RequirePauseAdminOrOwner        => match access_control::utils::require_pause_admin_or_owner(&e, &nondet_address()){_=>()},
            Action::RequirePauseOrEmergencyPauseAdminOrOwner => match access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &nondet_address()){_=>()},
            Action::RequireRewardsAdminOrOwner      => match access_control::utils::require_rewards_admin_or_owner(&e, &nondet_address()){_=>()},
            Action::NewAccessControl                => match access_control::access::AccessControl::new(&e){_=>()},
        }
        
        return action;
    }
    
}
/**
 * Asaf:
 * added to_string method for clog!
 */
pub fn role_to_string(role : &Role){
    match role {
        Role::Admin => clog!("Admin"),
        Role::EmergencyAdmin => clog!("EmergencyAdmin"),
        Role::RewardsAdmin => clog!("RewardsAdmin"),
        Role::OperationsAdmin => clog!("OperationsAdmin"),
        Role::PauseAdmin => clog!("PauseAdmin"),
        Role::EmergencyPauseAdmin => clog!("EmergencyPauseAdmin"),
    }
}