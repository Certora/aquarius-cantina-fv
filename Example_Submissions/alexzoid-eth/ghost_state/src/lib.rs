#![no_std]
#![allow(static_mut_refs)]

use soroban_sdk::{Address, BytesN, Vec};

static mut GHOST_STATE: Option<GhostState> = None;

// Structure to hold all system state
#[derive(Clone)]
pub struct GhostState {
    // Role addresses
    pub admin: Option<Address>,
    pub emergency_admin: Option<Address>,
    pub rewards_admin: Option<Address>,
    pub operations_admin: Option<Address>,
    pub pause_admin: Option<Address>,
    pub emergency_pause_admins: Vec<Address>,
    
    // Transfer deadlines
    pub admin_transfer_deadline: u64,
    pub em_admin_transfer_deadline: u64,
    
    // Future addresses
    pub future_admin: Option<Address>,
    pub future_em_admin: Option<Address>,
    
    // Emergency and upgrade
    pub emergency_mode: bool,
    pub upgrade_deadline: u64,
    pub future_wasm: Option<BytesN<32>>,
}

impl GhostState {

    pub fn new(emergency_pause_admins: Vec<Address>) -> Self {
        Self {
            admin: None,
            emergency_admin: None,
            rewards_admin: None,
            operations_admin: None,
            pause_admin: None,
            emergency_pause_admins,
            admin_transfer_deadline: 0,
            em_admin_transfer_deadline: 0,
            future_admin: None,
            future_em_admin: None,
            emergency_mode: false,
            upgrade_deadline: 0,
            future_wasm: None,
        }
    }
    
    pub fn initialize(state: Self) {
        unsafe {
            GHOST_STATE = Some(state);
        }
    }
    
    pub fn read() -> Self {
        unsafe {
            match &GHOST_STATE {
                Some(state) => state.clone(),
                None => panic!("GHOST_STATE not initialized. Call initialize first."),
            }
        }
    }
    
    pub fn update<F>(updater: F) 
    where 
        F: FnOnce(&mut GhostState)
    {
        unsafe {
            if let Some(ref mut state) = GHOST_STATE {
                updater(state);
            } else {
                panic!("GHOST_STATE not initialized. Call initialize first.");
            }
        }
    }
}