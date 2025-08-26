// Access control permission properties - organized by GhostState variables

use soroban_sdk::Env;
use cvlr::cvlr_assert;
use crate::certora_specs::base::ParametricParams;
use ghost_state::GhostState;

// 
// Role addresses
// 

// Check permissions for admin role changes
pub fn permissions_admin_role_changes(
    _e: &Env,
    params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.admin != after.admin {
        if before.admin.is_none() {
            // Initial admin setting - allowed during initialization
            true
        } else {
            // Admin role changes require current admin
            params.caller == before.admin.unwrap()
        }
    } else {
        // No change - always valid
        true
    };
    
    cvlr_assert!(valid);
}

// Check permissions for other admin role changes (emergency, rewards, operations, pause, emergency_pause)
pub fn permissions_other_admins_role_changes(
    _e: &Env,
    params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = {
        // Check if any of the other admin roles changed
        let emergency_admin_changed = before.emergency_admin != after.emergency_admin;
        let rewards_admin_changed = before.rewards_admin != after.rewards_admin;
        let operations_admin_changed = before.operations_admin != after.operations_admin;
        let pause_admin_changed = before.pause_admin != after.pause_admin;
        let emergency_pause_admins_changed = before.emergency_pause_admins != after.emergency_pause_admins;
        
        // If any role changed, only admin can make the change
        if emergency_admin_changed || rewards_admin_changed || operations_admin_changed || 
           pause_admin_changed || emergency_pause_admins_changed {
            before.admin.is_some() && params.caller == before.admin.unwrap()
        } else {
            // No change - always valid
            true
        }
    };
    
    cvlr_assert!(valid);
}

// 
// TRANSFER DEADLINES
// 

// Check permissions for admin_transfer_deadline changes
pub fn permissions_admin_transfer_deadline_changes(
    _e: &Env,
    params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.admin_transfer_deadline != after.admin_transfer_deadline {
        // Only admin can change admin transfer deadlines
        before.admin.is_some() && params.caller == before.admin.unwrap()
    } else {
        // No change - always valid
        true
    };
    
    cvlr_assert!(valid);
}

// Check permissions for em_admin_transfer_deadline changes
pub fn permissions_em_admin_transfer_deadline_changes(
    _e: &Env,
    params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.em_admin_transfer_deadline != after.em_admin_transfer_deadline {
        // Only admin can change emergency admin transfer deadlines
        before.admin.is_some() && params.caller == before.admin.unwrap()
    } else {
        // No change - always valid
        true
    };
    
    cvlr_assert!(valid);
}

// 
// FUTURE ADDRESSES
// 

// Check permissions and consistency for future_admin changes
pub fn permissions_future_admin_changes(
    _e: &Env,
    params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.future_admin != after.future_admin {
        // Only admin can change future_admin
        let admin_permission_valid = before.admin.is_some() && params.caller == before.admin.unwrap();
        
        // Check consistency with transfer deadline
        let consistency_valid = {
            if before.admin_transfer_deadline == 0 && after.admin_transfer_deadline != 0 {
                // Commit: future_admin should be set
                after.future_admin.is_some()
            } else if before.admin_transfer_deadline != 0 && after.admin_transfer_deadline == 0 {
                // Apply/Revert: future_admin should be cleared
                after.future_admin.is_none()
            } else {
                // Other cases: depends on deadline state
                true
            }
        };
        
        admin_permission_valid && consistency_valid
    } else {
        // No change - always valid
        true
    };
    
    cvlr_assert!(valid);
}

// Check permissions and consistency for future_em_admin changes
pub fn permissions_future_em_admin_changes(
    _e: &Env,
    params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.future_em_admin != after.future_em_admin {
        // Only admin can change future_em_admin
        let admin_permission_valid = before.admin.is_some() && params.caller == before.admin.unwrap();
        
        // Check consistency with transfer deadline
        let consistency_valid = {
            if before.em_admin_transfer_deadline == 0 && after.em_admin_transfer_deadline != 0 {
                // Commit: future_em_admin should be set
                after.future_em_admin.is_some()
            } else if before.em_admin_transfer_deadline != 0 && after.em_admin_transfer_deadline == 0 {
                // Apply/Revert: future_em_admin should be cleared
                after.future_em_admin.is_none()
            } else {
                // Other cases: depends on deadline state
                true
            }
        };
        
        admin_permission_valid && consistency_valid
    } else {
        // No change - always valid
        true
    };
    
    cvlr_assert!(valid);
}

// 
// EMERGENCY AND UPGRADE
// 

// Check permissions for emergency_mode changes
pub fn permissions_emergency_mode_changes(
    _e: &Env,
    params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.emergency_mode != after.emergency_mode {
        // Only emergency admin can change emergency mode
        before.emergency_admin.is_some() && 
        params.caller == before.emergency_admin.unwrap()
    } else {
        // No change - always valid
        true
    };
    
    cvlr_assert!(valid);
}

// Check permissions for upgrade_deadline changes
pub fn permissions_upgrade_deadline_changes(
    _e: &Env,
    params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.upgrade_deadline != after.upgrade_deadline {
        // Only admin can change upgrade deadlines
        before.admin.is_some() && params.caller == before.admin.unwrap()
    } else {
        // No change - always valid
        true
    };
    
    cvlr_assert!(valid);
}

// Check permissions and consistency for future_wasm changes
pub fn permissions_future_wasm_changes(
    _e: &Env,
    params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.future_wasm != after.future_wasm {
        // Only admin can change future_wasm
        let admin_permission_valid = before.admin.is_some() && params.caller == before.admin.unwrap();
        
        // Check consistency with upgrade deadline
        let consistency_valid = {
            if before.upgrade_deadline == 0 && after.upgrade_deadline != 0 {
                // Commit: future_wasm should be set
                after.future_wasm.is_some()
            } else if before.upgrade_deadline != 0 && after.upgrade_deadline == 0 {
                // Apply/Revert: future_wasm should be cleared
                after.future_wasm.is_none()
            } else {
                // Other cases: depends on deadline state
                true
            }
        };
        
        admin_permission_valid && consistency_valid
    } else {
        // No change - always valid
        true
    };
    
    cvlr_assert!(valid);
}