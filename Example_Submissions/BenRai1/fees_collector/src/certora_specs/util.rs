use access_control::role;
use cvlr::nondet;
use soroban_sdk::Address;
use soroban_sdk::String as SorobanString;
use soroban_sdk::Env;
use soroban_sdk::Symbol;

use access_control::management::SingleAddressManagementTrait;
use access_control::access::AccessControlTrait;
use access_control::role::Role;
use access_control::storage::DataKey;
use access_control::transfer::TransferOwnershipTrait;


use crate::certora_specs::ACCESS_CONTROL;

    // function to get the address of any role
    pub fn get_role_address_any_safe(role: &Role) -> Option<Address> {
        let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
        return acc_ctrl.as_ref().unwrap().get_role_safe(role);
    }

    // // function to get the future address safe
    // pub fn get_future_role_address_safe(role: &Role) -> Option<Address> {
    //     let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    //     acc_ctrl.as_ref().and_then(|ctrl| ctrl.get_future_address(role))
    // }

    //get the enum index of the role
    pub fn get_index_for_role(role: &Role) -> i64 {
        match role {
            Role::Admin => 0,
            Role::EmergencyAdmin => 1,
            Role::RewardsAdmin => 2,
            Role::OperationsAdmin => 3,
            Role::PauseAdmin => 4,
            Role::EmergencyPauseAdmin => 5,
            _ => panic!("Invalid role number"),
        }
    }

    //get the key based on a role
    pub fn get_key_for_role(role: &Role) -> DataKey {
        if role == &Role::Admin{
            DataKey::Admin
        } else if role == &Role::EmergencyAdmin {
            DataKey::EmergencyAdmin
        } else if role == &Role::RewardsAdmin {
            DataKey::Operator
        } else if role == &Role::OperationsAdmin {
            DataKey::OperationsAdmin
        } else if role == &Role::PauseAdmin {
            DataKey::PauseAdmin
        } else {
            DataKey::EmPauseAdmins
        }
    }

    

    // get name of role
    pub fn role_as_string(role: &Role) -> &'static str {
        match role {
            Role::Admin => "Admin",
            Role::EmergencyAdmin => "EmergencyAdmin",
            Role::RewardsAdmin => "RewardsAdmin",
            Role::OperationsAdmin => "OperationsAdmin",
            Role::PauseAdmin => "PauseAdmin",
            Role::EmergencyPauseAdmin => "EmergencyPauseAdmin",
            _ => "other"
        }
    }

    //get name from symbol
    pub fn symbol_as_string(e: &Env, value: &Symbol) -> &'static str {
            if value == &Symbol::new(e, "Admin") {
                return "Admin";
            } else if value == &Symbol::new(e, "EmergencyAdmin") {
                return "EmergencyAdmin";
            } else if value == &Symbol::new(e, "RewardsAdmin") {
                return "RewardsAdmin";
            } else if value == &Symbol::new(e, "OperationsAdmin") {
                return "OperationsAdmin";
            } else if value == &Symbol::new(e, "PauseAdmin") {
                return "PauseAdmin";
            } else if value == &Symbol::new(e, "EmergencyPauseAdmin") {
                return "EmergencyPauseAdmin";
            }
            "other"
    }


    // get number of role
    pub fn index_of_role(role: &Role) -> i64 {
        match role {
            Role::Admin => 0,
            Role::EmergencyAdmin => 1,
            Role::RewardsAdmin => 2,
            Role::OperationsAdmin => 3,
            Role::PauseAdmin => 4,
            Role::EmergencyPauseAdmin => 5,
            _ => 6
        }
    }

    // get the enum index of the symbol
    pub fn index_of_symbol(e:&Env, symbol: &Symbol) -> i64 {
        if symbol == &Symbol::new(&e, "Admin") {
        return 0;
        } else if symbol == &Symbol::new(e, "EmergencyAdmin") {
            return 1;
        } else if symbol == &Symbol::new(e, "RewardsAdmin") {
            return 2;
        } else if symbol == &Symbol::new(e, "OperationsAdmin") {
            return 3;
        } else if symbol == &Symbol::new(e, "PauseAdmin") {
            return 4;
        } else if symbol == &Symbol::new(e, "EmergencyPauseAdmin") {
            return 5;
        }
        6
    }

    // get symbol from number
    pub fn symbol_from_index(e: &Env, index: &i64) -> Symbol {
        match index {
            0 => Symbol::new(&e, "Admin"),
            1 => Symbol::new(&e, "EmergencyAdmin"),
            2 => Symbol::new(&e, "RewardsAdmin"),
            3 => Symbol::new(&e, "OperationsAdmin"),
            4 => Symbol::new(&e, "PauseAdmin"),
            5 => Symbol::new(&e, "EmergencyPauseAdmin"),
            _ => panic!("Invalid role number"),
        }
    }

    pub fn assume_role_in_scope(role: &Role) -> i64 {
        match role {
            Role::Admin => 1,
            Role::EmergencyAdmin => 1,
            Role::RewardsAdmin => 1,
            Role::OperationsAdmin => 1,
            Role::PauseAdmin => 1,
            Role::EmergencyPauseAdmin => 1,
            _ => 0
        }
    } 

    //generate randome role in scope
    pub fn nondet_role() -> Role { 
        let random_number: i64 = cvlr::nondet();
        let role_index = random_number % 6;
        match role_index {
            0 => Role::Admin,
            1 => Role::EmergencyAdmin,
            2 => Role::RewardsAdmin,
            3 => Role::OperationsAdmin,
            4 => Role::PauseAdmin,
            5 => Role::EmergencyPauseAdmin,
            _ => panic!("Invalid role number"),
        }
    }

     //generate randome Symbol in scope
    pub fn nondet_symbol(e: &Env) -> Symbol {
        let random_number: i64 = cvlr::nondet();
        let role_index = random_number % 6;
        match role_index {
            0 => Symbol::new(&e, "Admin"),
            1 => Symbol::new(&e, "EmergencyAdmin"),
            2 => Symbol::new(&e, "RewardsAdmin"),
            3 => Symbol::new(&e, "OperationsAdmin"),
            4 => Symbol::new(&e, "PauseAdmin"),
            5 => Symbol::new(&e, "EmergencyPauseAdmin"),
            _ => panic!("Invalid role number"),
        }
    }
   



//----------OLD CODE START------------------
    pub fn get_role_address() -> Address {
        let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
        return acc_ctrl.as_ref().unwrap().get_role(&Role::Admin);
    }


    pub fn is_role(address: &Address, role: &Role) -> bool {
        let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
        return acc_ctrl.as_ref().unwrap().address_has_role(&address, role)
    }

//----------OLD CODE END------------------