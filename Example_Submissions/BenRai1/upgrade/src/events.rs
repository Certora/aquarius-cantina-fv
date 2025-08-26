use soroban_sdk::{BytesN, Env, Symbol, Vec};
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

    pub fn commit_upgrade(&self, new_wasms: Vec<BytesN<32>>) {
        unsafe {
            GHOST_EVENT_COUNTER += 1; // Increment the ghost event counter
        }
        self.env()
            .events()
            .publish((Symbol::new(self.env(), "commit_upgrade"),), new_wasms)
    }

    pub fn apply_upgrade(&self, new_wasms: Vec<BytesN<32>>) {
        unsafe {
            GHOST_EVENT_COUNTER += 20; // Increment the ghost event counter
        }
        self.env()
            .events()
            .publish((Symbol::new(self.env(), "apply_upgrade"),), new_wasms)
    }

    pub fn revert_upgrade(&self) {
        unsafe {
            GHOST_EVENT_COUNTER += 300; // Increment the ghost event counter
        }
        self.env()
            .events()
            .publish((Symbol::new(self.env(), "revert_upgrade"),), ())
    }
}
