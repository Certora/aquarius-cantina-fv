// Log GhostState fields

use cvlr::clog;
use ghost_state::GhostState;

pub fn ghost_log_all() {
    let state = GhostState::read();
    
    match &state.admin {
        Some(addr) => {
            let admin_addr = cvlr_soroban::Addr(&addr);
            clog!(admin_addr);
        },
        None => {
            let admin_addr = 0u32;
            clog!(admin_addr);
        }
    }
    
    match &state.emergency_admin {
        Some(addr) => {
            let emergency_admin_addr = cvlr_soroban::Addr(&addr);
            clog!(emergency_admin_addr);
        },
        None => {
            let emergency_admin_addr = 0u32;
            clog!(emergency_admin_addr);
        }
    }
    
    match &state.rewards_admin {
        Some(addr) => {
            let rewards_admin_addr = cvlr_soroban::Addr(&addr);
            clog!(rewards_admin_addr);
        },
        None => {
            let rewards_admin_addr = 0u32;
            clog!(rewards_admin_addr);
        }
    }
    
    match &state.operations_admin {
        Some(addr) => {
            let operations_admin_addr = cvlr_soroban::Addr(&addr);
            clog!(operations_admin_addr);
        },
        None => {
            let operations_admin_addr = 0u32;
            clog!(operations_admin_addr);
        }
    }
    
    match &state.pause_admin {
        Some(addr) => {
            let pause_admin_addr = cvlr_soroban::Addr(&addr);
            clog!(pause_admin_addr);
        },
        None => {
            let pause_admin_addr = 0u32;
            clog!(pause_admin_addr);
        }
    }
    
    let emergency_pause_admins_count = state.emergency_pause_admins.len();
    clog!(emergency_pause_admins_count);
    
    let admin_transfer_deadline = state.admin_transfer_deadline;
    clog!(admin_transfer_deadline);
    
    let em_admin_transfer_deadline = state.em_admin_transfer_deadline;
    clog!(em_admin_transfer_deadline);
    
    match &state.future_admin {
        Some(addr) => {
            let future_admin_addr = cvlr_soroban::Addr(&addr);
            clog!(future_admin_addr);
        },
        None => {
            let future_admin_addr = 0u32;
            clog!(future_admin_addr);
        }
    }
    
    match &state.future_em_admin {
        Some(addr) => {
            let future_em_admin_addr = cvlr_soroban::Addr(&addr);
            clog!(future_em_admin_addr);
        },
        None => {
            let future_em_admin_addr = 0u32;
            clog!(future_em_admin_addr);
        }
    }
    
    let emergency_mode = state.emergency_mode;
    clog!(emergency_mode);
    
    let upgrade_deadline = state.upgrade_deadline;
    clog!(upgrade_deadline);
    
    let future_wasm_exists = match &state.future_wasm {
        Some(_) => 1u32,
        None => 0u32,
    };
    clog!(future_wasm_exists);
}