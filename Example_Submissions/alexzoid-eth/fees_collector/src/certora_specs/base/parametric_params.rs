// Support functions params in parametric rules

use soroban_sdk::{Address, Symbol, Env, Vec};
use cvlr_soroban::nondet_address;

#[derive(Clone)]
pub struct ParametricParams {
    pub caller: Address,
    pub new_address: Address,
    pub value: bool,
    pub role: Option<Symbol>,
    // access_control_harness
    pub emergency_admin: Address,
    pub rewards_admin: Address,
    pub operations_admin: Address,
    pub pause_admin: Address,
    pub emergency_pause_admins: Vec<Address>,
    pub addresses: Vec<Address>,
}

impl ParametricParams {
    pub fn new(env: &Env) -> Self {
        Self {
            caller: nondet_address(),
            new_address: nondet_address(),
            value: cvlr::nondet::<bool>(),
            role: None,
            emergency_admin: nondet_address(),
            rewards_admin: nondet_address(),
            operations_admin: nondet_address(),
            pause_admin: nondet_address(),
            emergency_pause_admins: Vec::new(env),
            addresses: Vec::new(env),
        }
    }
    
    pub fn with_caller(mut self, caller: Address) -> Self {
        self.caller = caller;
        self
    }
    
    pub fn with_new_address(mut self, new_address: Address) -> Self {
        self.new_address = new_address;
        self
    }
    
    pub fn with_value(mut self, value: bool) -> Self {
        self.value = value;
        self
    }
    
    pub fn with_role(mut self, role: Symbol) -> Self {
        self.role = Some(role);
        self
    }
    
    pub fn with_emergency_admin(mut self, emergency_admin: Address) -> Self {
        self.emergency_admin = emergency_admin;
        self
    }
    
    pub fn with_rewards_admin(mut self, rewards_admin: Address) -> Self {
        self.rewards_admin = rewards_admin;
        self
    }
    
    pub fn with_operations_admin(mut self, operations_admin: Address) -> Self {
        self.operations_admin = operations_admin;
        self
    }
    
    pub fn with_pause_admin(mut self, pause_admin: Address) -> Self {
        self.pause_admin = pause_admin;
        self
    }
    
    pub fn with_emergency_pause_admins(mut self, emergency_pause_admins: Vec<Address>) -> Self {
        self.emergency_pause_admins = emergency_pause_admins;
        self
    }
    
    pub fn with_addresses(mut self, addresses: Vec<Address>) -> Self {
        self.addresses = addresses;
        self
    }
}