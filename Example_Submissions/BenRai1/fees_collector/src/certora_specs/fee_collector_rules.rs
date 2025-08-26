use access_control::constants::ADMIN_ACTIONS_DELAY;
use access_control::emergency;
use soroban_sdk::{Address, Env, Vec, BytesN};
// use soroban_sdk::Env;

use cvlr::asserts::cvlr_assert as assert;
use cvlr::asserts::cvlr_assume as assume;
use cvlr::cvlr_satisfy as satisfy;
use cvlr::{clog, nondet};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;

use crate::certora_specs::util as util;
pub use crate::contract::FeesCollector;
pub use access_control::access::AccessControl;
use access_control::role::{self, Role};
use upgrade;

use crate::interface::AdminInterface;
use upgrade::interface::UpgradeableContract;
use access_control::interface::TransferableContract;
use access_control::transfer::TransferOwnershipTrait;
use access_control::management::SingleAddressManagementTrait;
use access_control::management::MultipleAddressesManagementTrait;
use access_control::role::SymbolRepresentation;
use access_control::access::{self, AccessControlTrait};
use access_control::storage::StorageTrait;
use upgrade::constants::UPGRADE_DELAY;
use soroban_sdk::Symbol;
use cvlr::log::cvlr_log;
use cvlr_soroban::is_auth;
use access_control::storage::DataKey;
use upgrade::storage::get_upgrade_deadline;


//------------------------------- RULES TEST START ----------------------------------

   //USE GHOST TO BYPASS THE RESTRICTIONS WITH THE VECTROS
    
    


    



    



   


   


    
   
    


  

   
//------------------------------- RULES TEST END ----------------------------------



//------------------------------- RULES OK START ------------------------------------
    //invariant: only admin can call
   // transfer_delayed_checked(): set_role_addresses
    // get_role_addresses(): reverts if role does not have many users
    
    // require_pause_or_emergency_pause_admin_or_owner(): reverts if address does not have adminRole or PauseAdmin or EmergencyPauseAdmin
    #[rule]
    fn require_pause_or_emergency_pause_admin_or_owner_reverts(e: Env) { //@audit-issue works when #[cfg(feature = "certora")] is not used
        let emergency_pause_admin = nondet_address();
        clog!(cvlr_soroban::Addr(&emergency_pause_admin));
        unsafe{
            ::access_control::GHOST_EMERGANCY_PAUSE_ADMIN = Some(emergency_pause_admin.clone());
        }
        let address = nondet_address();
        clog!(cvlr_soroban::Addr(&address));
        let access_control = AccessControl::new(&e);
        assume!(!access_control.address_has_role(&address, &Role::PauseAdmin) &&
                emergency_pause_admin != address &&
                !access_control.address_has_role(&address, &Role::Admin));
        access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);
        assert!(false); // should not reach and therefore should pass
    }

    // require_pause_or_emergency_pause_admin_or_owner(): passes if address has adminRole
    #[rule]
    fn require_pause_or_emergency_pause_admin_or_owner_passes_for_admin(e: Env, address: Address) { //@audit-issue works when #[cfg(feature = "certora")] is not used
        let access_control = AccessControl::new(&e);
        assume!(access_control.address_has_role(&address, &Role::Admin));
        assume!(!access_control.address_has_role(&address, &Role::PauseAdmin));
        assume!(!access_control.address_has_role(&address, &Role::EmergencyPauseAdmin));
        access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);
        satisfy!(true); // should not reach and therefore should pass
    }
    
    // require_pause_or_emergency_pause_admin_or_owner(): passes if address has PauseAdmin
    #[rule]
    fn require_pause_or_emergency_pause_admin_or_owner_passes_for_pause_admin(e: Env, address: Address) { //@audit-issue works when #[cfg(feature = "certora")] is not used
        let access_control = AccessControl::new(&e);
        assume!(!access_control.address_has_role(&address, &Role::Admin));
        assume!(access_control.address_has_role(&address, &Role::PauseAdmin));
        assume!(!access_control.address_has_role(&address, &Role::EmergencyPauseAdmin));
        access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);
        satisfy!(true); // should not reach and therefore should pass
    }

    //set_role_addresses():should pass for EmergancyPauseAdmin
    #[rule]
    fn set_role_addresses_passes_for_emergency_pause_admin(e: Env, addresses: Vec<Address>) {
        //set vector for emergany pause admin
        let address = nondet_address();
        let mut addresses = Vec::new(&e);
        addresses.push_back(address.clone());
        let role = Role::EmergencyPauseAdmin;
        let access_control = AccessControl::new(&e);
        access_control.set_role_addresses(&role, &addresses);
        satisfy!(true); // should pass
    }
    

    // commit_upgrade(): must work
    #[rule]
    fn commit_upgrade_must_work(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        //admin did authorization
        assume!(is_auth(admin.clone()));
        //admin has admin role
        let role = Role::Admin;
        let access_control = AccessControl::new(&e);
        assume!(access_control.address_has_role(&admin, &role));
        //upgrade deadline is not set
        let upgrade_deadline = get_upgrade_deadline(&e);
        assume!(upgrade_deadline == 0, "Upgrade deadline is not zero, another action is active");
        //call the function
        FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash);
        satisfy!(true, "Commit upgrade did not work as expected");
    }

    // apply_transfer_ownership(): returns future address
    #[rule]
    fn apply_transfer_ownership_returns_future_address(e: Env) {
        //get a random role
        let role_name = util::nondet_role();
        let role_symbol = role_name.as_symbol(&e);
        //get future address
        let expected_address = FeesCollector::get_future_address(e.clone(), role_symbol);
        //call the function
        let access_control = AccessControl::new(&e);
        let address = access_control.apply_transfer_ownership(&role_name);
        assert!(address == expected_address, "Future address does not match expected value");
    }

    // role_to_key(): apply_transfer_ownership
    #[rule]
    fn invariant_role_to_key_for_apply_transfer_ownership(e: Env, admin: Address, role_name: Symbol ) {
        invariant_role_to_key(3, || {
            FeesCollector::apply_transfer_ownership(e, admin, role_name);
        });
    }

    //apply_transfer_ownership(): reverts if future value is not set
    #[rule]
    fn apply_transfer_ownership_reverts_if_future_value_not_set(e: Env, admin: Address) {
        let role_name = util::nondet_symbol(&e);
        assume!(role_name == Symbol::new(&e, "Admin") || role_name == Symbol::new(&e, "EmergencyAdmin"));
        //get role from symbol
        let role = Role::from_symbol(&e, role_name.clone());
        //get future address and make sure it is none
        let access_control = AccessControl::new(&e);
        let future_key = access_control.get_future_key(&role);
        let future_address: Option<Address> = e.storage().instance().get(&future_key);
        //assume the future address is not set
        assume!(future_address.is_none());
        //call the apply_transfer_ownership function
        FeesCollector::apply_transfer_ownership(e, admin, role_name);
        assert!(false); // should not reach and therefore should pass
    }
    
    //invariant: role is transformed to key
    fn invariant_role_to_key<F>(amount: u32, f: F) where F: FnOnce() {
        //set counter to 0
        unsafe {
            ::access_control::GHOST_GET_KEY_COUNTER = 0; 
        }
        //call the function
        f();
        //assert that the get_key was called amount times
        let new_counter = unsafe {::access_control::GHOST_GET_KEY_COUNTER};
        clog!("Get key counter", new_counter);
        assert!(new_counter == amount);
    }

    // role_to_key(): init_admin
    #[rule]
    fn invariant_role_to_key_for_init_admin(e: Env, address: Address) {
        invariant_role_to_key(3, || {
            FeesCollector::init_admin(e, address);
        });
    }

    // role_to_key(): address_has_role
    #[rule]
    fn invariant_role_to_key_for_address_has_role(e: Env, address: Address ) {
        let role = util::nondet_role();
        let has_many_users = role.has_many_users();
        assume!(has_many_users); // to ensure address_has_role is called
        invariant_role_to_key(1, || {
            let access_control = AccessControl::new(&e);
            access_control.address_has_role(&address, &role);
        });
    }
    
    // role_to_key(): set_role_addresses
    #[rule]
    fn invariant_role_to_key_for_set_role_addresses(e: Env, role: Role, addresses: Vec<Address>) { 
        invariant_role_to_key(1, || {
            let access_control = AccessControl::new(&e);
            access_control.set_role_addresses(&role, &addresses);
        });
    }

    #[rule]
    fn get_role_addresses_reverts_if_role_does_not_have_many_users(e: Env) {
        let role = util::nondet_role();
        assume!(role != Role::EmergencyPauseAdmin);
        let access_control = AccessControl::new(&e);
        access_control.get_role_addresses(&role);
        assert!(false); // should not reach and therefore should pass
    }
    
    //init_admin: must set the admin address
    #[rule]
    pub fn init_admin_must_set_admin(e: Env) {
        let address = nondet_address();
        //admin is not set yet
        assume!(util::get_role_address_any_safe(&Role::Admin).is_none());
        FeesCollector::init_admin(e, address.clone());
        let addr = util::get_role_address();
        satisfy!(addr == address);
    }

    // get_role_addresses(): returns the right vector
    #[rule]
    fn get_role_addresses_returns_right_vector(e: Env) {
        //set vectro for Emergany
        let address = nondet_address();
        let mut addresses = Vec::new(&e);
        addresses.push_back(address.clone());
        //set the role address
        let role = Role::EmergencyPauseAdmin;
        let access_control = AccessControl::new(&e);
        access_control.set_role_addresses(&role, &addresses);
        let addresses_return = access_control.get_role_addresses(&role);
        assert!(addresses == addresses_return, "Addresses do not match expected value");
    }

    // get_key(): returns the right key
    #[rule]
    fn get_key_returns_right_key(e: Env) {
        let role = util::nondet_role();
        let access_control = AccessControl::new(&e);
        let key = access_control.get_key(&role);
        let expected_key= util::get_key_for_role(&role); 
        assert!(key == expected_key, "Key does not match expected value");
    }

    // get_transfer_ownership_deadline(): reverts for all but admin and emergancyAdmin
    #[rule]
    fn get_transfer_ownership_deadline_reverts_for_all_but_admin_and_emergency_admin(e: Env, role: Role) {
        assume!(role != Role::Admin && role != Role::EmergencyAdmin);
        let access_control = AccessControl::new(&e);
        access_control.get_transfer_ownership_deadline(&role);
        assert!(false); // should not reach and therefore should pass
    }
    
    // get_transfer_ownership_deadline(): returns right deadline
    #[rule]
    fn get_transfer_ownership_deadline_returns_right_deadline(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        //assert role_name is only admin or emergency admin
        assume!(role_name == Symbol::new(&e, "Admin") || role_name == Symbol::new(&e, "EmergencyAdmin"));
        let role = Role::from_symbol(&e, role_name.clone());

        //call commit_transfer_ownership to set the deadline
        FeesCollector::commit_transfer_ownership(e.clone(), admin, role_name, new_address);

        //get the deadline
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);

        let target_deadline = e.ledger().timestamp() + ADMIN_ACTIONS_DELAY;
        assert!(deadline == target_deadline, "Deadline does not match expected value");
    }

    // has_many_users(): returns true only for EmergangcyPauseAdmin
    #[rule]
    fn has_many_users_returns_true_only_for_emergency_pause_admin(e: Env) {
        let role = util::nondet_role();
        let has_many_users = role.has_many_users();
        if role == Role::EmergencyPauseAdmin {
            assert!(has_many_users);
        } else {
            assert!(!has_many_users);
        }
    }

    //invariant: converts symbol to role
    fn invariant_symbol_to_role<F>(amount: u32, f: F) where F: FnOnce() {
        //set counter to 0
        unsafe {
            ::access_control::GHOST_FROM_SYMBOL_COUNTER = 0; 
        }
        //call the function
        f();
        //assert that the from_symbol was called amount times
        let new_counter = unsafe {::access_control::GHOST_FROM_SYMBOL_COUNTER};
        clog!("From symbol counter", new_counter);
        assert!(new_counter == amount);
    }

    // symbol_to_role(): commit_transfer_ownership
    #[rule]
    fn invariant_symbol_to_role_for_commit_transfer_ownership(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        invariant_symbol_to_role(1, || {
            FeesCollector::commit_transfer_ownership(e, admin, role_name, new_address);
        });
    }
    
    // symbol_to_role(): apply_transfer_ownership
    #[rule]
    fn invariant_symbol_to_role_for_apply_transfer_ownership(e: Env, admin: Address, role_name: Symbol) {
        invariant_symbol_to_role(1, || {
            FeesCollector::apply_transfer_ownership(e, admin, role_name);
        });
    }
    
    // symbol_to_role(): revert_transfer_ownership
    #[rule]
    fn invariant_symbol_to_role_for_revert_transfer_ownership(e: Env, admin: Address, role_name: Symbol) {
        invariant_symbol_to_role(1, || {
            FeesCollector::revert_transfer_ownership(e, admin, role_name);
        });
    }
    
    // symbol_to_role(): get_future_address
    #[rule]
    fn invariant_symbol_to_role_for_get_future_address(e: Env) {
        let role_name = util::nondet_symbol(&e);
        invariant_symbol_to_role(1, || {
            FeesCollector::get_future_address(e, role_name);
        });
    }

    //invariant: event was emitted in access
    fn invariant_event_access<F>(amount: u32, f: F) where F: FnOnce() {
        //set counter to 0
        unsafe {
            ::access_control::GHOST_EVENT_COUNTER = 0; 
        }
        //call the function
        f();
        //assert that the event was emitted amount times
        let new_counter = unsafe {::access_control::GHOST_EVENT_COUNTER};
        clog!("As symbol counter", new_counter);
        assert!(new_counter == amount);
    }

    // event_access(): commit_transfer_ownership
    #[rule]
    fn invariant_event_access_for_commit_transfer_ownership(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        invariant_event_access(1, || {
            FeesCollector::commit_transfer_ownership(e, admin, role_name, new_address);
        });
    }

    // event_access(): apply_transfer_ownership
    #[rule]
    fn invariant_event_access_for_apply_transfer_ownership(e: Env, admin: Address, role_name: Symbol) {
        invariant_event_access(20, || {
            FeesCollector::apply_transfer_ownership(e, admin, role_name);
        });
    }

    // event_access(): revert_transfer_ownership
    #[rule]
    fn invariant_event_access_for_revert_transfer_ownership(e: Env, admin: Address, role_name: Symbol) {
        invariant_event_access(300, || {
            FeesCollector::revert_transfer_ownership(e, admin, role_name);
        });
    }

    //event_access(): set_emergency_mode
    #[rule]
    fn invariant_event_access_for_set_emergency_mode(e: Env, admin: Address, value: bool) {
        invariant_event_access(50000, || {
            FeesCollector::set_emergency_mode(e, admin, value);
        });
    }

    //invariant: emit event update
    fn invariant_emit_event_updated<F>(amount: u32, f: F) where F: FnOnce() {
        //set counter to 0
        unsafe {
            ::upgrade::GHOST_EVENT_COUNTER = 0; 
        }
        //call the function
        f();
        //assert that the event was emitted amount times
        let new_counter = unsafe {::upgrade::GHOST_EVENT_COUNTER};
        clog!("As symbol counter", new_counter);
        assert!(new_counter == amount);
    }

    // emited_event_upgrade(): commit_upgrade
    #[rule]
    fn emited_event_upgrade_commit_upgrade(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        invariant_emit_event_updated(1, || {
            FeesCollector::commit_upgrade(e, admin, new_wasm_hash);
        });
    }
    
    // emited_event_upgrade(): apply_upgrade
    #[rule]
    fn emited_event_upgrade_apply_upgrade(e: Env, admin: Address) {
        invariant_emit_event_updated(20, || {
            FeesCollector::apply_upgrade(e, admin);
        });
    }
    
    // emited_event_upgrade(): revert_upgrade
    #[rule]
    fn emited_event_upgrade_revert_upgrade(e: Env, admin: Address) {
        invariant_emit_event_updated(300, || {
            FeesCollector::revert_upgrade(e, admin);
        });
    }

    //invariant: checks if role has many users
    fn invariant_transfer_deadline_checked<F>( amount: u32, f: F) where F: FnOnce() {
        //set counter to 0
        unsafe {
            ::access_control::GHOST_TRANSFER_DEADLINE_COUNTER = 0; 
        }
        //call the function
        f();
        //assert that the it was checked if the role is transfer delayed
        let new_counter = unsafe {::access_control::GHOST_TRANSFER_DEADLINE_COUNTER};
        clog!("Transfer Deadline counter", new_counter);
        assert!(new_counter == amount);
    }

    // transfer_deadline_checked(): commit_transfer_ownership
    #[rule]
    fn invariant_transfer_deadline_checked_for_commit_transfer_ownership(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        invariant_transfer_deadline_checked(1, || {
            FeesCollector::commit_transfer_ownership(e, admin, role_name, new_address);
        });
    }
    
    // transfer_deadline_checked(): get_future_address
    #[rule]
    fn invariant_transfer_deadline_checked_for_get_future_address(e: Env,) {
        let role_name = util::nondet_symbol(&e);
        invariant_transfer_deadline_checked(1, || {
            FeesCollector::get_future_address(e, role_name);
        });
    }
   
    // transfer_deadline_checked(): apply_transfer_ownership 
    #[rule]
    fn invariant_transfer_deadline_checked_for_apply_transfer_ownership(e: Env, admin: Address, role_name: Symbol) {
        //ensure role has value
        let current_address = util::get_role_address_any_safe(&Role::from_symbol(&e, role_name.clone()));
        assume!(current_address.is_some()); // to ensure transfer_deadline is checked
        invariant_transfer_deadline_checked(2, || {
            FeesCollector::apply_transfer_ownership(e, admin, role_name);
        });
    }
    
    //invariant: checks if role has many users
    fn invariant_has_many_users_checked<F>( amount: u32, f: F) where F: FnOnce() {
        //set counter to 0
        unsafe {
            ::access_control::GHOST_HAS_MANY_USERS_COUNTER = 0; 
        }
        //call the function
        f();
        //assert that the it was checked if the role is transfer delayed
        let new_counter = unsafe {::access_control::GHOST_HAS_MANY_USERS_COUNTER};
        clog!("Has_many_users counter", new_counter);
        assert!(new_counter == amount);
    }

    // has_many_users_checked(): commit_transfer_ownership
    #[rule]
    fn invariant_has_many_users_checked_for_commit_transfer_ownership(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        invariant_has_many_users_checked(3, || {
            FeesCollector::commit_transfer_ownership(e, admin, role_name, new_address);
        });
    }

    // has_many_users_checked(): set_role_address
    #[rule]
    fn invariant_has_many_users_checked_for_set_role_address(e: Env, role: Role, address: Address) {
        invariant_has_many_users_checked(2, || {
            let access_control = AccessControl::new(&e);
            access_control.set_role_address(&role, &address);
        });
    }
    
    // has_many_users_checked(): get_role_addresses
    #[rule]
    fn invariant_has_many_users_checked_for_get_role_addresses(e: Env, role: Role) {
        invariant_has_many_users_checked(1, || {
            let access_control = AccessControl::new(&e);
            access_control.get_role_addresses(&role);
        });
    }
    
    // has_many_users_checked(): set_role_addresses
    #[rule]
    fn invariant_has_many_users_checked_for_set_role_addresses(e: Env, role: Role, addresses: Vec<Address>) {
        invariant_has_many_users_checked(1, || {
            let access_control = AccessControl::new(&e);
            access_control.set_role_addresses(&role, &addresses);
        });
    }
    
    // has_many_users_checked(): get_future_address
    #[rule]
    fn invariant_has_many_users_checked_for_get_future_address(e: Env) {
        invariant_has_many_users_checked(1, || {
            let role = util::nondet_role();
            let access_control = AccessControl::new(&e);
            access_control.get_future_address(&role);
        });
    }

    //invariant: checks if role is transfer delayed
    fn invariant_transfer_delayed_checked<F>( amount: u32, f: F) where F: FnOnce() {
        //set counter to 0
        unsafe {
            ::access_control::GHOST_TRANSFER_DELAYED_COUNTER = 0; 
        }
        //call the function
        f();
        //assert that the it was checked if the role is transfer delayed
        let new_counter = unsafe {::access_control::GHOST_TRANSFER_DELAYED_COUNTER};
        clog!("Transfer delayed counter", new_counter);
        assert!(new_counter == amount);
    }

    // transfer_delayed_checked(): commit_transfer_ownership
    #[rule]
    fn invariant_transfer_delayed_checked_for_commit_transfer_ownership(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        invariant_transfer_delayed_checked(1, || {
            FeesCollector::commit_transfer_ownership(e, admin, role_name, new_address);
        });
    }

    //transfer_delayed_checked(): set_role_addresses
    #[rule]
    fn invariant_transfer_delayed_checked_for_set_role_addresses(e: Env, addresses: Vec<Address>) {
        let role = util::nondet_role();
        invariant_transfer_delayed_checked(1, || {
            let access_control = AccessControl::new(&e);
            access_control.set_role_addresses(&role, &addresses);
        });
    }
    
    // transfer_delayed_checked(): get_future_address
    #[rule]
    fn invariant_transfer_delayed_checked_for_get_future_address(e: Env) {
        let role = util::nondet_role();
        invariant_transfer_delayed_checked(1, || {
            let access_control = AccessControl::new(&e);
            access_control.get_future_address(&role);
        });
    }

   //invariant: bump_instance is called
    fn invariant_bump_instance_is_called<F>( amount: u32, f: F) where F: FnOnce() {
        //set counter to 0
        unsafe {
            ::utils::GHOST_BUMP_COUNTER = 0; 
        }
        //call the function
        f();
        //assert that the bump_instance is called amount times
        let new_counter = unsafe {::utils::GHOST_BUMP_COUNTER};
        clog!("Bump counter", new_counter);
        assert!(new_counter == amount);
    }

    // bump_instance_called(): get_emergency_mode
    #[rule]
    fn invariant_bump_instance_called_for_get_emergency_mode(e: Env) {
        invariant_bump_instance_is_called(1, || {
            FeesCollector::get_emergency_mode(e);
        });
    }
    
    // bump_instance_called(): set_emergency_mode
    #[rule]
    fn invariant_bump_instance_called_for_set_emergency_mode(e: Env, admin: Address, value: bool) {
        invariant_bump_instance_is_called(2, || {
            FeesCollector::set_emergency_mode(e, admin, value);
        });
    }
    
    // bump_instance_called(): set_role_address
    #[rule]
    fn invariant_bump_instance_called_for_set_role_address(e: Env, role: Role, address: Address) {
        invariant_bump_instance_is_called(2, || {
            let access_control = AccessControl::new(&e);
            access_control.set_role_address(&role, &address);
        });
    }
    
    // bump_instance_called(): get_role_addresses
    #[rule]
    fn invariant_bump_instance_called_for_get_role_addresses(e: Env, role: Role) {
        invariant_bump_instance_is_called(1, || {
            let access_control = AccessControl::new(&e);
            access_control.get_role_addresses(&role);
        });
    }
    
    // bump_instance_called(): set_role_addresses
    #[rule]
    fn invariant_bump_instance_called_for_set_role_addresses(e: Env, role: Role, addresses: Vec<Address>) {
        invariant_bump_instance_is_called(1, || {
            let access_control = AccessControl::new(&e);
            access_control.set_role_addresses(&role, &addresses);
        });
    }

    // bump_instance_called(): commit_transfer_ownership
    #[rule]
    fn invariant_bump_instance_called_for_commit_transfer_ownership(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        invariant_bump_instance_is_called(4, || {
            FeesCollector::commit_transfer_ownership(e.clone(), admin, role_name, new_address);
        });
    }
    
    // bump_instance_called(): apply_transfer_ownership
    #[rule]
    fn invariant_bump_instance_called_for_apply_transfer_ownership(e: Env, admin: Address, ) {
        //assume that role has a value set
        let role_name: Symbol = util::nondet_symbol(&e);
        let role = Role::from_symbol(&e, role_name.clone());
        let current_address = util::get_role_address_any_safe(&role);
        assume!(current_address.is_some()); // to ensure bump_instance is called 5 times
        invariant_bump_instance_is_called(5, || {
            FeesCollector::apply_transfer_ownership(e.clone(), admin, role_name);
        });
    }
   
    //INVARIANT: only admin can call a function
    fn invariant_only_admin_can_call<F>(admin: Address, f: F) where F: FnOnce() {
        //assume the addmin did not give authorization
        assume!(!is_auth(admin.clone()));
        //call the function
        f();
        //assert that the function did not succeed
        assert!(false); // should not reach and therefore should pass
    }

    //invariant: commit_transfer_ownership(): only admin can call
    #[rule]
    fn invariant_only_admin_can_call_commit_transfer_ownership(e: Env, admin: Address, new_address: Address) {
        let role_name = util::nondet_symbol(&e);
        invariant_only_admin_can_call(admin.clone(), || {
            FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone());
        });
    }

    // set_role_addresses(): passes for EmergancyPauseAdmin
    #[rule]
    fn set_role_addresses_passes_for_emergancy_paus_admin(e: Env, addresses: &Vec<Address>) { 
        let role = Role::EmergencyPauseAdmin;
        let access_control = AccessControl::new(&e);
        access_control.set_role_addresses(&role, addresses);
        satisfy!(true); 
    }
    
    // set_role_addresses(): reverts if role does not have many users
    #[rule]
    fn set_role_addresses_reverts_if_role_does_not_have_many_users(e: Env, addresses: &Vec<Address>) { 
            let access_control = AccessControl::new(&e);
            let role = util::nondet_role();
            assume!(role != Role::EmergencyPauseAdmin);
            let role_number = util::index_of_role(&role);
            clog!("Role number", role_number);

            access_control.set_role_addresses(&Role::Admin, addresses);
            assert!(false); // should not reach and therefore should pass
        }

    // commit_transfer_ownership(): reverts if caller is not adminAddress (require_auth())
    #[rule]
    fn commit_transfer_ownership_reverts_if_not_admin(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        //assume the admin did not authorize this call
        assume!(!is_auth(admin.clone()));
        FeesCollector::commit_transfer_ownership(e, admin, role_name, new_address);
        assert!(false); // should not reach and therefore should pass
    }
    
    // apply_transfer_ownership(): reverts if caller is not adminAddress require_auth()
    #[rule]
    fn apply_transfer_ownership_reverts_if_not_admin(e: Env, admin: Address, role_name: Symbol) {
        //assume the admin did not authorize this call
        assume!(!is_auth(admin.clone()));
        FeesCollector::apply_transfer_ownership(e, admin, role_name);
        assert!(false); // should not reach and therefore should pass
    }
    
    // revert_transfer_ownership(): reverts if caller is not adminAddress require_auth()
    #[rule]
    fn revert_transfer_ownership_reverts_if_not_admin(e: Env, admin: Address, role_name: Symbol) {
        //assume the admin did not authorize this call
        assume!(!is_auth(admin.clone()));
        FeesCollector::revert_transfer_ownership(e, admin, role_name);
        assert!(false); // should not reach and therefore should pass
    }

    // commit_upgrade(): reverts if caller is not adminAddress (require_auth())
    #[rule]
    fn commit_upgrade_reverts_if_admin_not_auth(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        //assume the admin did not authorize this call
        assume!(!is_auth(admin.clone()));
        FeesCollector::commit_upgrade(e, admin, new_wasm_hash);
        assert!(false); // should not reach and therefore should pass
    }
    
    // apply_upgrade(): reverts if caller is not adminAddress (require_auth())
    #[rule]
    fn apply_upgrade_reverts_if_admin_not_auth(e: Env, admin: Address) {
        //assume the admin did not authorize this call
        assume!(!is_auth(admin.clone()));
        FeesCollector::apply_upgrade(e, admin);
        assert!(false); // should not reach and therefore should pass
    }
    
    // revert_upgrade(): reverts if caller is not adminAddress (require_auth())
    #[rule]
    fn revert_upgrade_reverts_if_admin_not_auth(e: Env, admin: Address) {
        //assume the admin did not authorize this call
        assume!(!is_auth(admin.clone()));
        FeesCollector::revert_upgrade(e, admin);
        assert!(false); // should not reach and therefore should pass
    }
    
    // set_emergency_mode(): reverts if caller is not emergancy_adminAddress require_auth()
    #[rule]
    fn set_emergency_mode_reverts_if_not_emergency_admin(e: Env, emergency_admin: Address, value: bool) {
        //assume the emergency_admin did not authorize this call
        assume!(!is_auth(emergency_admin.clone()));
        FeesCollector::set_emergency_mode(e, emergency_admin, value);
        assert!(false); // should not reach and therefore should pass
    }

    // apply_upgrade(): returns new_wasm_hash
    #[rule]
    fn apply_upgrade_returns_new_wasm(e: Env, admin: Address) {
        let future_wasm = upgrade::storage::get_future_wasm(&e);
        let return_value = FeesCollector::apply_upgrade(e.clone(), admin);
        assert!(future_wasm == Some(return_value));
    }
    
    // set_role_address(): works for Admin not set
    #[rule]
    fn set_role_address_works_for_admin_if_not_set(e: Env, role: Role, address: Address) {
        //assume role is admin
        assume!(role == Role::Admin);
        //assume the address is not set
        let current_address = util::get_role_address_any_safe(&role);
        assume!(current_address.is_none());
        //call
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&role, &address);
        // get the address
        let role_address = util::get_role_address_any_safe(&role);
        satisfy!(role_address == Some(address));
    }

    //set_role_address(): always works for OperationsAdmin
    #[rule]
    fn set_role_address_works_for_operations_admin(e: Env, role: Role, address: Address) {
        //assume the address is already set
        let current_address = util::get_role_address_any_safe(&Role::OperationsAdmin);
        assume!(current_address == Some(address.clone()));
        //assume the role is OperationsAdmin
        assume!(role == Role::OperationsAdmin);
        // call
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&role, &address);
        // get the address
        let role_address = util::get_role_address_any_safe(&role);
        satisfy!(role_address == Some(address));
    } 

    //set_role_address(): always works for PauseAdmin
    #[rule]
    fn set_role_address_works_for_pause_admin(e: Env, role: Role, address: Address) {
        //assume the address is already set
        let current_address = util::get_role_address_any_safe(&Role::PauseAdmin);
        assume!(current_address == Some(address.clone()));
        //assume the role is PauseAdmin
        assume!(role == Role::PauseAdmin);
        // call
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&role, &address);
        // get the address
        let role_address = util::get_role_address_any_safe(&role);
        satisfy!(role_address == Some(address));
    }

    // set_role_address(): always works for rewardsAdmin
    #[rule]
    fn set_role_address_works_for_rewards_admin(e: Env, address: Address) { 
        let current_address = util::get_role_address_any_safe(&Role::RewardsAdmin);
        assume!(current_address == Some(address.clone()));
        let role = Role::RewardsAdmin;
        // call
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&role, &address);
        // get the address
        let role_address = util::get_role_address_any_safe(&role);
        satisfy!(role_address == Some(address));
    }

    // set_role_address(): sets the right address for the right role
    #[rule]
    fn set_role_address_sets_right_address(e: Env, address: Address, role: Role){
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&role, &address);
        let final_address = util::get_role_address_any_safe(&role);
        assert!(address == Option::expect(final_address, "no address"));
    }

    // set_role_address(): reverts if admin/emergancyAdmin are already set
    #[rule]
    fn set_role_address_reverts_if_already_set(e: Env, role: Role, address: Address){
        assume!(role == Role::Admin || role == Role::EmergencyAdmin);
        // role is already set
        let is_set = util::get_role_address_any_safe(&role).is_some();
        assume!(is_set);
        // call
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&role, &address);
        assert!(false); // should not reach and therefore should pass
    }

    // set_role_address(): reverts if role is_some and has transfer_delay
    #[rule]
    fn set_role_address_reverts_if_some_and_delay(e: Env, role: Role, address: Address) {
        // role has transfer delay
        let has_transfer_delay = role.is_transfer_delayed();
        assume!(has_transfer_delay);
        //role is already set
        let is_set = util::get_role_address_any_safe(&role).is_some();
        assume!(is_set);
        // call
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&role, &address);
        assert!(false); // should not reach and therefore should pass
    }
    
    // set_role_address(): reverts if role has multiple users
    #[rule]
    fn set_role_address_reverts_if_multiple_users(e: Env, role: Role, address: Address) {
        // role has multiple users
        let has_many_users = role.has_many_users();
        assume!(has_many_users);
        // call
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&role, &address);
        assert!(false); // should not reach and therefore should pass
    }
    
    // set_role_address(): reverts for EmergancyPauseAdmin
    #[rule]
    fn set_role_address_reverts_for_emergancypauseadmin(e: Env, role: Role, address: Address){
        assume!(role == Role::EmergencyPauseAdmin);
        //call
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&role, &address);
        assert!(false); // should not reach and therefore should pass
    }

    // get_future_deadline_key(): reverts if role is not Admin or EmergancyAdmin
    #[rule]
    fn get_future_deadline_key_reverts_not_admin_or_emergency_admin(e: Env, role: Role) {
        assume!(role != Role::Admin && role != Role::EmergencyAdmin);
        let access_control = AccessControl::new(&e);
        access_control.get_future_deadline_key(&role); 
        assert!(false); // should not reach and therefore should pass
    }

    // get_future_deadline_key(): returns the right key for the given role
    #[rule]
    fn get_future_deadline_key_returns_right_key(e: Env, role: Role) {
        assume!(role == Role::Admin || role == Role::EmergencyAdmin);
        let access_control = AccessControl::new(&e);
        let key = access_control.get_future_deadline_key(&role);
        let expected_key = if role == Role::Admin {
            access_control::storage::DataKey::TransferOwnershipDeadline
        } else {
            access_control::storage::DataKey::EmAdminTransferOwnershipDeadline
        };
        assert!(key == expected_key);
    }

    // get_future_key(): reverts if role is not Admin or EmergancyAdmin
    #[rule]
    fn get_future_key_reverts_not_admin_or_emergency_admin(e: Env, role: Role) {
        assume!(role != Role::Admin && role != Role::EmergencyAdmin);
        let access_control = AccessControl::new(&e);
        access_control.get_future_key(&role); 
        assert!(false); // should not reach and therefore should pass
    }

    // get_future_key(): returns the right key for the given role
    #[rule]
    fn get_future_key_returns_right_key(e: Env, role: Role) {
        assume!(role == Role::Admin || role == Role::EmergencyAdmin);
        let access_control = AccessControl::new(&e);
        let key = access_control.get_future_key(&role);
        let expected_key = if role == Role::Admin {
            access_control::storage::DataKey::FutureAdmin
        } else {
            access_control::storage::DataKey::FutureEmergencyAdmin
        };
        assert!(key == expected_key);
    }

    // get_future_address(): reverts if role is not Admin or EmergancyAdmin
    #[rule]
    fn get_future_address_reverts_not_admin_or_emergency_admin(e: Env, role_name: Symbol) {
        let role = Role::from_symbol(&e, role_name.clone());
        assume!(role != Role::Admin && role != Role::EmergencyAdmin);
        FeesCollector::get_future_address(e.clone(), role_name.clone()); 
        assert!(false); // should not reach and therefore should pass
    }

    // revert_transfer_ownership(): set deadline to 0 for the used role
    #[rule]
    fn revert_transfer_ownership_sets_deadline_to_zero(e: Env, admin: Address, role_name: Symbol) {
        FeesCollector::revert_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        // get transfer_ownership_deadline 
        let role = Role::from_symbol(&e, role_name.clone());
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        assert!(deadline == 0); 
    }

    // revert_transfer_ownership(): reverts if adminAddress does not have adminRole
    #[rule]
    fn revert_transfer_ownership_reverts_if_no_admin_role(e: Env, admin: Address, role_name: Symbol) {
        assume!(!util::is_role(&admin, &Role::Admin));
        FeesCollector::revert_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        assert!(false); // should not reach and therefore should pass
    }
   
    // apply_transfer_ownership(): sets address to futureAddress
    #[rule]
    fn apply_transfer_ownership_sets_adress_to_future_address(e: Env, admin: Address, role_name: Symbol) {
        // get transfer_ownership_deadline 
        let role = Role::from_symbol(&e, role_name.clone());
        let access_control = AccessControl::new(&e);
        let future_address = access_control.get_future_address(&role);
        let current_address = util::get_role_address_any_safe(&role);
        assume!(current_address.is_some());
        assume!(future_address != Option::expect(current_address, "no value"));
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        // get the address
        let address = util::get_role_address_any_safe(&role);
        assert!(address == Some(future_address));
    }

    // apply_transfer_ownership(): if role is not set yet, deadline is not respected
    #[rule]
    fn apply_transfer_ownership_does_not_respect_deadline_if_role_not_set(e: Env, admin: Address, role_name: Symbol) {
        // get transfer_ownership_deadline 
        let role = Role::from_symbol(&e, role_name.clone());
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        let current_address = util::get_role_address_any_safe(&role);
        assume!(current_address.is_none());
        assume!(deadline != 0 && e.ledger().timestamp() < deadline);
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        satisfy!(true); 
    }
    
    // apply_transfer_ownership(): sets transfer_ownership_deadline to 0
    #[rule]
    fn apply_transfer_ownership_sets_deadline_to_zero(e: Env, admin: Address, role_name: Symbol) {
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        // get transfer_ownership_deadline 
        let role = Role::from_symbol(&e, role_name.clone());
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        assert!(deadline == 0); 
    }

    // apply_transfer_ownership(): reverts if dedline has not passed yet
    #[rule]
    fn apply_transfer_ownership_reverts_if_deadline_not_passed(e: Env, admin: Address, role_name: Symbol) {
        // get transfer_ownership_deadline 
        let role = Role::from_symbol(&e, role_name.clone());
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        let current_address = util::get_role_address_any_safe(&role);
        assume!(current_address.is_some());
        assume!(deadline != 0 && e.ledger().timestamp() < deadline);
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        assert!(false); // should not reach and therefore should pass
    }
    
    // apply_transfer_ownership(): reverts if transfer_ownership_deadline == 0
    #[rule]
    fn apply_transfer_ownership_reverts_if_deadline_zero(e: Env, admin: Address, role_name: Symbol) {
        // get transfer_ownership_deadline 
        let role = Role::from_symbol(&e, role_name.clone());
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        assume!(deadline == 0);
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        assert!(false); // should not reach and therefore should pass
    }
   
    // apply_transfer_ownership(): reverts if role is not Admin or EmergancyAdmin
    #[rule]
    fn apply_transfer_ownership_reverts_not_admin_or_eadmin(e: Env, admin: Address, role_name: Symbol) {
        assume!(role_name != Symbol::new(&e, "Admin") && role_name != Symbol::new(&e, "EmergencyAdmin"));
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        assert!(false); // should not reach and therefore should pass
    }

    // apply_transfer_ownership(): reverts if adminAddress does not have adminRole
    #[rule]
    fn apply_transfer_ownership_reverts_if_caller_not_admin(e: Env, admin: Address, role_name: Symbol) {
        let access_control = AccessControl::new(&e);
        let is_admin = access_control.address_has_role(&admin, &Role::Admin);
        assume!(is_admin == false); 
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        assert!(false); // should not reach and therefore should pass
    }

    // get_future_address(): returns the set address if there is no transfer scheduled
    #[rule]
    fn get_future_address_returns_set_address_if_no_transfer_scheduled(e: Env, role_name: Symbol) {
        //get the address
        let role = Role::from_symbol(&e, role_name.clone());
        let address = util::get_role_address_any_safe(&role);
        assume!(address.is_some());
        let address = address.unwrap();
        //make sure that the transfer_ownership_deadline is 0
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        assume!(deadline == 0);
        //call get_future_address
        let future_address = FeesCollector::get_future_address(e.clone(), role_name.clone());
        //make sure the address is the same
        assert!(future_address == address);
    }
    
    // get_future_address(): returns the future address if shedule is set 
    #[rule]
    fn get_future_address_returns_future_address_if_scheduled(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        //shedule transfer
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone());
        //call get_future_address
        let future_address = FeesCollector::get_future_address(e.clone(), role_name.clone());
        //make suer the address is the same
        assert!(future_address == new_address);
    }

    // get_future_address(): must work for Admin
    #[rule]
    fn get_future_address_works_for_admin(e: Env, role_name: Symbol) {
        //assume the role is Admin
        assume!(role_name == Symbol::new(&e, "Admin"));
        //get the address
        let role = Role::from_symbol(&e, role_name.clone());
        let address = util::get_role_address_any_safe(&role);
        assume!(address.is_some());
        let address = address.unwrap();
        //make sure that the transfer_ownership_deadline is 0
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        assume!(deadline == 0);
        //call get_future_address
        let future_address = FeesCollector::get_future_address(e.clone(), role_name.clone());
        //make sure the address is the same
        satisfy!(future_address == address);
    }

    // commit_transfer_ownership(): sets future_address to new_address
    #[rule]
    fn commit_transfer_ownership_set_future_address(e: Env) {
    
        let new_address: Address = nondet_address();
        let admin: Address = nondet_address();
        // check for Admin or EmergencyAdmin
        let value = cvlr::nondet();
        let role_name: Symbol;
        if value { role_name = Symbol::new(&e, "EmergencyAdmin")} else { role_name = Symbol::new(&e, "Admin")};
        
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone());
        // FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        let future_address = FeesCollector::get_future_address(e.clone(), role_name.clone()); 
        assert!(future_address == new_address); 
    }
    
    // commit_transfer_ownership(): reverts if transfer_ownership_deadline already set
    #[rule]
    fn commit_transfer_ownership_reverts_if_deadline_set(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        // get transfer_ownership_deadline 
        let role = Role::from_symbol(&e, role_name.clone());
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        assume!(deadline != 0);
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone());
        assert!(false); // should not reach and therefore should pass
    }
    
    // commit_transfer_ownership(): sets transfer_ownership_deadline to timestamp() + ADMIN_ACTIONS_DELAY;
    #[rule]
    fn commit_transfer_ownership_sets_deadline(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone());
        // get transfer_ownership_deadline 
        let role = Role::from_symbol(&e, role_name.clone());
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        let target_deadline = e.ledger().timestamp() + ADMIN_ACTIONS_DELAY;
        assert!(deadline == target_deadline); // should not reach and therefore should pass
    }
    
    // commit_transfer_ownership(): reverts if role has many_users
    #[rule]
    fn commit_transfer_ownership_reverts_many_users(e: Env, new_address: Address, admin: Address , role_name: Symbol){
        let role = Role::from_symbol(&e, role_name.clone());
        let has_many_users = role.has_many_users();
        assume!(has_many_users == true);
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone()); 
        assert!(false); // should not reach and therefore should pass
    }

    // commit_transfer_ownership(): reverts if role has no transfer_delay
    #[rule]
    fn commit_transfer_ownership_reverts_if_no_transfer_delay(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        let role = Role::from_symbol(&e, role_name.clone());
        let has_transfer_delay = role.is_transfer_delayed();
        assume!(has_transfer_delay == false);
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone()); 
        assert!(false); // should not reach and therefore should pass
    }

    // commit_transfer_ownership(): must work for Admin and EmergencyAdmin
    #[rule]
    fn commit_transfer_ownership_works_for_admin_and_emergency_admin(e: Env, admin: Address, new_address: Address) {
        let mut role_name = Symbol::new(&e, "Admin");
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone()); 
        role_name = Symbol::new(&e, "EmergencyAdmin");
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone()); 
        satisfy!(true); // should not reach and therefore should pass
    }

    // commit_transfer_ownership(): reverts if role is not Admin or EmergancyAdmin
    #[rule]
    fn commit_transfer_ownership_reverts_not_admin_or_emergency_admin(e: Env) {
        let role_name = util::nondet_symbol(&e);
        assume!(role_name != Symbol::new(&e, "Admin") && role_name != Symbol::new(&e, "EmergencyAdmin"));
        let admin = nondet_address();
        let new_address: Address = nondet_address();
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone()); 
        assert!(false); 
    }
    
    // commit_transfer_ownership(): reverts if adminAddress does not have adminRole
    #[rule]
    fn commit_transfer_ownership_reverts_if_no_admin_role(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        let set_admin_address = util::get_role_address_any_safe(&Role::Admin);
        //set_admin_address not set or not the admin address
        assume!(!set_admin_address.is_some() || set_admin_address.is_some() && set_admin_address.unwrap() != admin );
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone()); 
        assert!(false); // should not reach and therefore should pass
    }

    // TRANSFER_OWNERSHIP: once committed, no new commit possibel before applied or cancled
    #[rule]
    fn transfer_ownership_reverts_if_already_commited(e: Env) {
        let new_address: Address = nondet_address();
        let admin: Address = nondet_address();
        // check for Admin or EmergencyAdmin
        let value = cvlr::nondet();
        let role_name: Symbol;
        if value { role_name = Symbol::new(&e, "EmergencyAdmin")} else { role_name = Symbol::new(&e, "Admin")};
        
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone());
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address.clone()); 
        assert!(false); 
    }
    
    // from_symbol(): reverts if symbol is not in the list
    #[rule]
    fn from_symbol_reverts_for_wrong_symbol(e: Env, symbol: Symbol) {
        //assume symbol is not in the list
        assume!(util::index_of_symbol(&e, &symbol) == 6);
        Role::from_symbol(&e, symbol);
        assert!(false); // should not reach and therefore should pass
    }

    // as_symbol(): must pass for all roles
    #[rule]
    fn as_symbol_works_for_all_roles(e: Env) {
        let mut role = Role::Admin;
        role.as_symbol(&e);
        role = Role::EmergencyAdmin;
        role.as_symbol(&e);
        role = Role::RewardsAdmin;
        role.as_symbol(&e);
        role = Role::OperationsAdmin;
        role.as_symbol(&e);
        role = Role::PauseAdmin;
        role.as_symbol(&e);
        role = Role::EmergencyPauseAdmin;
        role.as_symbol(&e);
        satisfy!(true);
    }

    // as_symbol(): fromSymbol => toSymbol => result is starting input
    #[rule]
    fn as_symbol_works(e: Env) {
            let role = util::nondet_role();
            let symbol = role.as_symbol(&e);
            let role2 = Role::from_symbol(&e, symbol);
            assert!(role == role2);
        }

    // TRANSFER_OWNERSHIP: once committed, can only be applied after ADMIN_ACTIONS_DELAY
    #[rule]
    fn transfer_ownership_must_respect_delay(e: Env) {
        let new_address: Address = nondet_address();
        let admin: Address = nondet_address();
        // check for Admin or EmergencyAdmin
        let value = cvlr::nondet();
        let role_name: Symbol;
        if value { role_name = Symbol::new(&e, "EmergencyAdmin")} else { role_name = Symbol::new(&e, "Admin")};
        
        FeesCollector::commit_transfer_ownership(e.clone(), admin.clone(), role_name.clone(), new_address);
        FeesCollector::apply_transfer_ownership(e.clone(), admin.clone(), role_name.clone()); 
        satisfy!(true); 
    }

    // as_symbol(): reverts if symbol is not in the list
    #[rule]
    fn as_symbol_reverts_for_wrong_role(e:Env, role: Role){
        let role_in_scope = util::assume_role_in_scope(&role);
        assume!(role_in_scope == 0);
        role.as_symbol(&e);
        // assert!(false); // should not reach and therefore should pass 
        satisfy!(true);
    }

    // get_role(): returns the set admin
    #[rule]
    fn get_role_returns_set_admin(e: Env) {
        let access_control = AccessControl::new(&e);
        let admin_role = Role::Admin;
        let role = util::nondet_role();
        let is_set = util::get_role_address_any_safe(&admin_role).is_some();
        assume!(is_set == true);
        let admin = util::get_role_address_any_safe(&admin_role).unwrap();
        let addr = access_control.get_role(&role);
        assert!(addr == admin);
    }

    // get_role(): reverts if admin is not set
    #[rule]
    fn get_role_reverts_if_admin_not_set(e: Env) {
        let role = util::nondet_role();
        let access_control = AccessControl::new(&e);
        let admin_role = Role::Admin;
        assume!(role == Role::Admin);
        let is_set = access_control.get_role_safe(&admin_role).is_some();
        assume!(is_set == false);
        access_control.get_role(&role);
        assert!(false); // should not reach and therefore should pass
    }

    // get_role(): reverts if role is not admin
    #[rule]
    fn get_role_reverts_if_role_not_admin(e: Env) {
        let role = util::nondet_role();
        let access_control = AccessControl::new(&e);
        assume!(role != Role::Admin);
        access_control.get_role(&role);
        assert!(false); // should not reach and therefore should pass
    }

   // set_role_addresses(): reverts if wrong role was given
    #[rule]
    fn set_role_addresses_reverts_if_wrong_role(e: Env, addresses: &Vec<Address>) { 
        let role = util::nondet_role();
        let access_control = AccessControl::new(&e);
        assume!(role != Role::EmergencyPauseAdmin);
        access_control.set_role_addresses(&role, addresses);
        assert!(false); // should not reach and therefore should pass
    }

    // set_role_addresses(): reverts if role has transfer_delay
    #[rule]
    fn set_role_addresses_reverts_transfer_delay(e: Env, role: Role, addresses: &Vec<Address>) { 
            let access_control = AccessControl::new(&e);
            let role_in_scope = util::assume_role_in_scope(&role);
            assume!(role_in_scope == 1);
            //role has transfer delay
            let role_transfer_delay = role.is_transfer_delayed();
            assume!(role_transfer_delay);
            //call
            access_control.set_role_addresses(&role, addresses);
            assert!(false); // should not reach and therefore should pass
    }
   
    // require_pause_or_emergency_pause_admin_or_owner(): passes if address has EmergencyPauseAdmin
    #[rule]
    fn require_pause_or_emergency_pause_admin_or_owner_passes_for_e_pause_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(!access_control.address_has_role(&address, &Role::Admin));
        assume!(!access_control.address_has_role(&address, &Role::PauseAdmin));
        assume!(access_control.address_has_role(&address, &Role::EmergencyPauseAdmin));
        access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);
        satisfy!(true); // should not reach and therefore should pass
    }
    
    // require_pause_admin_or_owner(): reverts if address does not have adminRole or pauseAdminRole
    #[rule]
    fn require_pause_admin_or_owner_reverts(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(!access_control.address_has_role(&address, &Role::PauseAdmin));
        assume!(!access_control.address_has_role(&address, &Role::Admin));
        access_control::utils::require_pause_admin_or_owner(&e, &address);
        assert!(false); // should not reach and therefore should pass
    }

    // require_pause_admin_or_owner(): passes if address has adminRole
    #[rule]
    fn require_pause_admin_or_owner_passes_for_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(access_control.address_has_role(&address, &Role::Admin));
        assume!(!access_control.address_has_role(&address, &Role::PauseAdmin));
        access_control::utils::require_pause_admin_or_owner(&e, &address);
        satisfy!(true); // should not reach and therefore should pass
    }
    
    // require_pause_admin_or_owner(): passes if address has pauseAdminRole
    #[rule]
    fn require_pause_admin_or_owner_passes_for_pause_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(!access_control.address_has_role(&address, &Role::Admin));
        assume!(access_control.address_has_role(&address, &Role::PauseAdmin));
        access_control::utils::require_pause_admin_or_owner(&e, &address);
        satisfy!(true); // should not reach and therefore should pass
    }

    // require_operations_admin_or_owner(): passes if address has adminRole
    #[rule]
    fn require_operations_admin_or_owner_passes_for_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(access_control.address_has_role(&address, &Role::Admin));
        assume!(!access_control.address_has_role(&address, &Role::OperationsAdmin));
        access_control::utils::require_operations_admin_or_owner(&e, &address);
        satisfy!(true);
    }
    
    // require_operations_admin_or_owner(): passes if address has operationsAdminRole
    #[rule]
    fn require_operations_admin_or_owner_passes_for_operational_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(!access_control.address_has_role(&address, &Role::Admin));
        assume!(access_control.address_has_role(&address, &Role::OperationsAdmin));
        access_control::utils::require_operations_admin_or_owner(&e, &address);
        satisfy!(true);
    }

    // require_operations_admin_or_owner(): reverts if address does not have adminRole or operationsAdminRole
    #[rule]
    fn require_operations_admin_or_owner_reverts(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(!access_control.address_has_role(&address, &Role::Admin));
        assume!(!access_control.address_has_role(&address, &Role::OperationsAdmin));
        access_control::utils::require_operations_admin_or_owner(&e, &address);
        assert!(false); // should not reach and therefore should pass
    }

    // require_rewards_admin_or_owner(): passes if address has adminRole
    #[rule]
    fn require_rewards_admin_or_owner_passes_for_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(access_control.address_has_role(&address, &Role::Admin));
        assume!(!access_control.address_has_role(&address, &Role::RewardsAdmin)); 
        access_control::utils::require_rewards_admin_or_owner(&e, &address);
        satisfy!(true);
    }

    // require_rewards_admin_or_owner(): passes if address has rewardAdminRole
    #[rule]
     fn require_rewards_admin_or_owner_passes_for_reward_admin(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(access_control.address_has_role(&address, &Role::RewardsAdmin)); 
        assume!(!access_control.address_has_role(&address, &Role::Admin));
        access_control::utils::require_rewards_admin_or_owner(&e, &address);
        satisfy!(true);
    }

    // require_rewards_admin_or_owner(): reverts if address does not have adminRole or rewardAdminRole
    #[rule]
    fn require_rewards_admin_or_owner_reverts(e: Env, address: Address) {
        let access_control = AccessControl::new(&e);
        assume!(!access_control.address_has_role(&address, &Role::Admin));
        assume!(!access_control.address_has_role(&address, &Role::RewardsAdmin));
        access_control::utils::require_rewards_admin_or_owner(&e, &address);
        assert!(false); // should not reach and therefore should pass
    }

    // version(): returns 150
    #[rule]
    fn version_returns_150(e: Env) {
        let version = FeesCollector::version();
        assert!(version == 150);
    }

    // get_future_address(): reverts if role not Admin or EmergancyAdmin
    #[rule]
    fn get_future_address_reverts_if_role_not_admin_or_emergency_admin(e: Env, role_name: Symbol) {
        let given_role = Role::from_symbol(&e, role_name.clone());
        assume!(given_role != Role::Admin);
        assume!(given_role != Role::EmergencyAdmin);
        FeesCollector::get_future_address(e.clone(), role_name);
        assert!(false); // should not reach and therefore should pass
    }
    
    // get_future_address(): reverts if no transfer scheduled and the roleAddress is not set
    #[rule]
    fn get_future_address_reverts_if_not_scheduled_and_no_address(e: Env) {
        let random_bool: bool = cvlr::nondet();
        
        let role_name :Symbol;
        if random_bool {
            role_name = Symbol::new(&e, "EmergencyAdmin");
        } else {
            role_name = Symbol::new(&e, "Admin");
        }

        let role = Role::from_symbol(&e, role_name.clone());
        //deadline for Admin transfer is set to 0
        let access_control = AccessControl::new(&e);
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        assume!(deadline == 0);
        //adminAddress is not set
        let is_set = util::get_role_address_any_safe(&role).is_some();
        assume!(is_set == false);
        // //get_future_address() should revert
        FeesCollector::get_future_address(e.clone(), role_name.clone());
        assert!(false);
    }
    
    // set_emergency_mode(): emergancyMode is set to "value"
    #[rule]
    fn set_emergency_mode_sets_emergency_mode(e: Env ) {
        let value = cvlr::nondet();
        FeesCollector::set_emergency_mode(e.clone(), e.current_contract_address(), value);
        let value_after = FeesCollector::get_emergency_mode(e.clone());
        assert!(value_after == value);
        
    }

    // set_emergency_mode(): reverts if emergancy_adminAddress does not have the emergancy_adminRole
    #[rule]
    fn set_emergency_mode_reverts_if_not_emergancy_admin(e: Env, emergancy_admin: Address, value: bool) {
        assume!(!util::is_role(&emergancy_admin, &Role::EmergencyAdmin));
        FeesCollector::set_emergency_mode(e.clone(), emergancy_admin, value);
        assert!(false); // should not reach and therefore should pass
    }

    // revert_upgrade(): reverts if adminAddress does not have adminRole
    #[rule]
    fn revert_upgrade_reverts_if_no_admin_role(e: Env, admin: Address) {
        assume!(!util::is_role(&admin, &Role::Admin));
        FeesCollector::revert_upgrade(e.clone(), admin);
        assert!(false); // should not reach and therefore should pass
    }
    
    // revert_upgrade(): sets upgrade_deadline == 0
    #[rule]
    fn revert_upgrade_sets_deadline_zero(e: Env, admin: Address) {
        FeesCollector::revert_upgrade(e.clone(), admin);
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        assert!(deadline == 0);
    }

    // apply_upgrade(): sets upgrade_deadline == 0
    #[rule]
    fn apply_upgrade_sets_deadline_zero(e: Env, admin: Address) {
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        assume!(deadline != 0);
        FeesCollector::apply_upgrade(e.clone(), admin.clone());
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        assert!(deadline == 0);
    }
  
    // apply_upgrade(): reverts if future_wasm == 0
    #[rule]
    fn apply_upgrade_reverts_if_future_wasm_zero(e: Env, admin: Address) {
        let future_wasm = upgrade::storage::get_future_wasm(&e);
        assume!(future_wasm.is_none());
        FeesCollector::apply_upgrade(e.clone(), admin);
        assert!(false); // should not reach and therefore should pass
    }

    // apply_upgrade(): no emergancyMode => reverts if upgrade_deadline has not passed
    #[rule]
    fn apply_upgrade_reverts_if_deadline_not_passed(e: Env, admin: Address) {
        //ensuer emergancy mode is not set
        let value: bool =  FeesCollector::get_emergency_mode(e.clone());
        assume!(value == false);
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        assume!(deadline > e.ledger().timestamp());
        FeesCollector::apply_upgrade(e.clone(), admin);
        assert!(false); // should not reach and therefore should pass
    }
  
    // apply_upgrade(): no emergancyMode => reverts if upgrade_deadline == 0
    #[rule]
    fn apply_upgrade_reverts_if_deadline_zero(e: Env, admin: Address) {
        //ensuer emergancy mode is not set
        let value: bool =  FeesCollector::get_emergency_mode(e.clone());
        assume!(value == false);
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        assume!(deadline == 0);
        FeesCollector::apply_upgrade(e.clone(), admin);
        assert!(false); // should not reach and therefore should pass
    }

    // apply_upgrade(): reverts if adminAddress does not have adminRole
    #[rule]
    fn apply_upgrade_reverts_if_no_admin_role(e: Env, admin: Address) {
        assume!(!util::is_role(&admin, &Role::Admin));
        FeesCollector::apply_upgrade(e.clone(), admin);
        assert!(false); // should not reach and therefore should pass
    }

     // commit_upgrade(): sets future_wasm to provided hash
    #[rule]
    fn commit_upgrade_sets_future_wasm(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        let future_wasm = upgrade::storage::get_future_wasm(&e);
        assume!(future_wasm.is_none());
        FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash.clone());
        let future_wasm = upgrade::storage::get_future_wasm(&e);
        assert!(future_wasm.is_some());
        if future_wasm.is_some(){
            assert!(future_wasm.unwrap() == new_wasm_hash);
        }
    }
    
    // commit_upgrade(): sets update_deadline = timestamp() + UPGREADE_DELAY
    #[rule]
    fn commit_upgrade_sets_update_deadline(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        assume!(deadline == 0);
        FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash);
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        let traget_deadline = e.ledger().timestamp() + UPGRADE_DELAY;
        assert!(deadline == traget_deadline);
    }
    
    // commit_upgrade(): reverts if upgrate_deadline != 0
    #[rule]
    fn commit_upgrade_reverts_if_upgrate_deadline_not_zero(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        let deadline = upgrade::storage::get_upgrade_deadline(&e);
        assume!(deadline != 0);
        FeesCollector::commit_upgrade(e, admin, new_wasm_hash);
        assert!(false); // should not reach and therefore should pass
    }
    
    // commit_upgrade(): reverts if adminAddress does not have adminRole
    #[rule]
    fn commit_upgrade_reverts_no_admin_role(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        assume!(!util::is_role(&admin, &Role::Admin));
        FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash);
        assert!(false); // should not reach and therefore should pass
    }
    
    // UPGRADE: in emergancyMode, an upgrade can be applied right away
    #[rule]
    fn upgrade_in_emergancy_mode_updated_without_delay(e: Env, admin: Address, new_wasm_hash: BytesN<32>){
        //ensuer emergancy mode is set
        let value: bool =  FeesCollector::get_emergency_mode(e.clone());
        assume!(value == true);

        FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash.clone());
        FeesCollector::apply_upgrade(e.clone(), admin.clone());
        satisfy!(true); 
    }

    // UPGRADE: once an upgrate is comitted, no new upgrate can be comitted befere the old one is applied or upgrated
    #[rule]
    fn upgrade_reverts_if_already_commited(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash.clone());
        FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash.clone());
        assert!(false); // should not reach and therefore should pass
    }
    
    // UPGRADE: once upgrate is comitted, the upgrade can only be triggered after UPGRADE_DELAY has passed (no emergancyMode)
    #[rule]
    fn upgrade_reverts_if_delay_not_passed(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        //ensuer emergancy mode is not set
        let value: bool =  FeesCollector::get_emergency_mode(e.clone());
        assume!(value == false);
        FeesCollector::commit_upgrade(e.clone(), admin.clone(), new_wasm_hash.clone());
        FeesCollector::apply_upgrade(e.clone(), admin.clone());
        assert!(false); // should not reach and therefore should pass
    }

    //init_admin(): reverts if admin is already set
    #[rule]
    pub fn init_admin_reverts_if_already_set(e: Env) {
        let address = nondet_address();
        clog!(cvlr_soroban::Addr(&address));
        let is_set = util::get_role_address_any_safe(&Role::Admin).is_some();
        assume!(is_set == true);

        let addr = util::get_role_address();
        clog!(cvlr_soroban::Addr(&address));

        assume!(addr == address);
        FeesCollector::init_admin(e, address.clone());
        assert!(false); // should not reach and therefore should pass
    }



//------------------------------- RULES OK END ------------------------------------




/**
 * These are some example rules to help get started.
*/
//--------------------- OLD RUELS START ---------------------
    #[rule]
    pub fn init_admin_sets_admin(e: Env) {
        let address = nondet_address();
        clog!(cvlr_soroban::Addr(&address));
        FeesCollector::init_admin(e, address.clone());
        let addr = util::get_role_address();
        // syntax of how to use `clog!`. This is helpful for calltrace when a rule fails.
        clog!(cvlr_soroban::Addr(&addr));
        assert!(addr == address);
    }

    #[rule]
    pub fn only_emergency_admin_sets_emergency_mode(e: Env) {
        let address = nondet_address();
        let value: bool = cvlr::nondet();
        assume!(!util::is_role(&address, &Role::EmergencyAdmin));
        FeesCollector::set_emergency_mode(e, address, value);
        assert!(false); // should not reach and therefore should pass
    }

    #[rule]
    pub fn set_emergency_mode_success(e: Env) {
        let value: bool = cvlr::nondet();
        access_control::emergency::set_emergency_mode(&e, &value);
        assert!(access_control::emergency::get_emergency_mode(&e) == value);
    }
// --------------------- OLD RUELS END ---------------------

//------------------------------- RULES PROBLEMS START ----------------------------------

    
    // // set_role_addresses(): gives the provided addresses the role 
    // #[rule]
    // fn set_role_addresses_gives_role(e: Env, addresses: &Vec<Address>, ) { //@audit-issue fails becasue of vector usage
    //     let role = Role::EmergencyPauseAdmin;
    //     assume!(addresses.len() == 1);
    //     let address = addresses.first().unwrap();
    //     clog!(cvlr_soroban::Addr(&address));
    //     let access_control = AccessControl::new(&e);
    //     access_control.set_role_addresses(&role, &addresses);
    //     // check if the addresses have the role
        
    //     let has_role = access_control.address_has_role(&address, &Role::EmergencyPauseAdmin);
    //     assert!(has_role);
    // }
      

    // // set_role_address(): works for EmergancyAdmin if not set
    // #[rule]
    // fn set_role_address_works_for_emergancy_admin_if_not_set(e: Env, role: Role, address: Address) { //@audit-issue PASSES but mutation deos not work even though it works for Admin
    //     //assume role is EmergencyAdmin
    //     assume!(role == Role::EmergencyAdmin);
    //     //assume the address is not set
    //     let current_address = util::get_role_address_any_safe(&role);
    //     assume!(current_address.is_none());
    //     //call
    //     let access_control = AccessControl::new(&e);
    //     access_control.set_role_address(&role, &address);
    //     // get the address
    //     let role_address = util::get_role_address_any_safe(&role);
    //     satisfy!(role_address == Some(address));
    // }
    
    // // transfer_delayed_checked(): set_role_address
    // //@audit-issue mutation fails, dont know why. Both current version and the use of the invariant fail to catch the mutation
    // #[rule]
    // fn invariant_transfer_delayed_checked_for_set_role_address(e: Env, address: Address) { 
    //     //set counter to 0
    //     unsafe {
    //         ::access_control::GHOST_TRANSFER_DELAYED_COUNTER = 0; 
    //     }
    //     let role = util::nondet_role();
    //     let current_address = util::get_role_address_any_safe(&role);
    //     let access_control = AccessControl::new(&e);
    //     access_control.set_role_address(&role, &address);
    //     if current_address.is_some() {
    //         unsafe{
    //             clog!("Transfer delayed counter IF", ::access_control::GHOST_TRANSFER_DELAYED_COUNTER);
    //             assert!(::access_control::GHOST_TRANSFER_DELAYED_COUNTER == 1); // should be called once
    //         }
    //     } else {
    //         unsafe{
    //             clog!("Transfer delayed counter ELSE", ::access_control::GHOST_TRANSFER_DELAYED_COUNTER);
    //             assert!(::access_control::GHOST_TRANSFER_DELAYED_COUNTER == 0); // should not be called
    //         }
    //     }
    //     // invariant_transfer_delayed_checked(1, || {
    //     //     let access_control = AccessControl::new(&e);
    //     //     access_control.set_role_address(&role, &address);
    //     // });
    // }
    

    // // address_has_role(): works for role with many users
    // #[rule]
    // fn address_has_role_many_users(e: Env) { //@audit-issue fails, also because of emergency pause admin (??)
    //     //set vector for emergany pause admin
    //     let address = nondet_address();
    //     let mut addresses = Vec::new(&e);
    //     addresses.push_back(address.clone());
    //     //set the role address
    //     let role = Role::EmergencyPauseAdmin;
    //     let access_control = AccessControl::new(&e);
    //     access_control.set_role_addresses(&role, &addresses);
    //     let has_role = access_control.address_has_role(&address, &role);
    //     assert!(has_role == true);
    // }

    
    






//------------------------------- RULES PROBLEMS END ----------------------------------