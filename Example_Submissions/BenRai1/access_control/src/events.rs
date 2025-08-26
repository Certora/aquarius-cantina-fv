use crate::role::{Role, SymbolRepresentation};
use soroban_sdk::{Address, Env, Symbol, Vec};
#[cfg(feature = "certora")]
use crate::GHOST_EVENT_COUNTER;

#[derive(Clone)]
pub struct Events(Env);

impl Events {
    #[inline(always)]
    pub fn env(&self) -> &Env {
        &self.0
    }

    #[inline(always)]
    pub fn new(env: &Env) -> Events {
        Events(env.clone())
    }

    pub fn commit_transfer_ownership(&self, role: Role, new_address: Address) {
        #[cfg(feature = "certora")]
        unsafe {
            GHOST_EVENT_COUNTER += 1; 
        }
        self.env().events().publish(
            (
                Symbol::new(self.env(), "commit_transfer_ownership"),
                role.as_symbol(self.env()),
            ),
            (new_address,),
        )
    }

    pub fn apply_transfer_ownership(&self, role: Role, new_owner: Address) {
        #[cfg(feature = "certora")]
        unsafe {
            GHOST_EVENT_COUNTER += 20; 
        }
        self.env().events().publish(
            (
                Symbol::new(self.env(), "apply_transfer_ownership"),
                role.as_symbol(self.env()),
            ),
            (new_owner,),
        )
    }

    pub fn revert_transfer_ownership(&self, role: Role) {
        #[cfg(feature = "certora")]
        unsafe {
            GHOST_EVENT_COUNTER += 300; 
        }
        self.env().events().publish(
            (
                Symbol::new(self.env(), "revert_transfer_ownership"),
                role.as_symbol(self.env()),
            ),
            (),
        )
    }

    pub fn set_privileged_addrs(
        &self,
        rewards_admin: Address,
        operations_admin: Address,
        pause_admin: Address,
        emergency_pause_admins: Vec<Address>,
    ) {
        #[cfg(feature = "certora")]
        unsafe {
            GHOST_EVENT_COUNTER += 4000; 
        }
        self.env().events().publish(
            (Symbol::new(self.env(), "set_privileged_addrs"),),
            (
                rewards_admin,
                operations_admin,
                pause_admin,
                emergency_pause_admins,
            ),
        )
    }

    pub fn set_emergency_mode(&self, emergency_mode: bool) {
        #[cfg(feature = "certora")]
        unsafe {
            GHOST_EVENT_COUNTER += 50000;
        }
        self.env().events().publish(
            match emergency_mode {
                true => (Symbol::new(self.env(), "enable_emergency_mode"),),
                false => (Symbol::new(self.env(), "disable_emergency_mode"),),
            },
            (),
        )
    }
}
