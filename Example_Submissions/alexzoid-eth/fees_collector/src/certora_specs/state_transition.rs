// State transition properties

use soroban_sdk::Env;
use cvlr::cvlr_assert;
use crate::certora_specs::base::ParametricParams;
use ghost_state::GhostState;
use access_control::constants::ADMIN_ACTIONS_DELAY;

fn check_upgrade_deadline_lifecycle(
    e: &Env,
    deadline_before: u64,
    deadline_after: u64,
    _future_before: Option<impl Clone>,
    future_after: Option<impl Clone>,
    emergency_mode_before: bool,
    _emergency_mode_after: bool,
) -> bool {
    if deadline_before == 0 && deadline_after != 0 {
        // Transition from 0 to non-zero (commit)
        deadline_after > e.ledger().timestamp() && future_after.is_some()
    } else if deadline_before != 0 && deadline_after == 0 {
        // Transition from non-zero to 0 (apply or revert)
        if emergency_mode_before {
            // In emergency mode, upgrade can be applied immediately
            future_after.is_none()
        } else {
            // Normal mode, must wait for deadline
            e.ledger().timestamp() >= deadline_before && future_after.is_none()
        }
    } else if deadline_before != 0 && deadline_after != 0 {
        // Cannot change non-zero deadline to different non-zero value
        deadline_before == deadline_after
    } else {
        true
    }
}

fn check_admin_deadline_lifecycle(
    e: &Env,
    deadline_before: u64,
    deadline_after: u64,
    future_after: Option<impl Clone>,
) -> bool {
    if deadline_before == 0 && deadline_after != 0 {
        // Transition from 0 to non-zero (commit)
        deadline_after == e.ledger().timestamp() + ADMIN_ACTIONS_DELAY && future_after.is_some()
    // } else if deadline_before != 0 && deadline_after == 0 {
        // Transition from non-zero to 0 (apply or revert)
        // @note This executable path is violated due 
        //  to https://github.com/alexzoid-eth/aquarius-cantina-fv/issues/2
        // future_after.is_none()
    } else if deadline_before != 0 && deadline_after != 0 {
        // Cannot change non-zero deadline to different non-zero value
        deadline_before == deadline_after
    } else {
        true
    }
}

// 
// Role addresses
// 

// Check time-gated role changes for Admin
pub fn state_transition_admin_role(
    e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.admin != after.admin {
        if before.admin.is_none() {
            // Initial setting is allowed
            after.admin.is_some()
        } else {
            // Must have gone through apply process
            before.admin_transfer_deadline != 0 &&
            after.admin_transfer_deadline == 0 &&
            e.ledger().timestamp() >= before.admin_transfer_deadline
        }
    } else {
        true
    };
    
    cvlr_assert!(valid);
}

// Check time-gated role changes for Emergency Admin
pub fn state_transition_emergency_admin_role(
    e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.emergency_admin != after.emergency_admin {
        if before.emergency_admin.is_some() {
            before.em_admin_transfer_deadline != 0 &&
            after.em_admin_transfer_deadline == 0 &&
            e.ledger().timestamp() >= before.em_admin_transfer_deadline
        } else {
            // Initial setting is allowed
            true
        }
    } else {
        true
    };
    
    cvlr_assert!(valid);
}

// Check that initial admin can only be set once
pub fn state_transition_admin_init_once(
    _e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    // If admin was already set, it can only change through transfer process
    let valid = if before.admin.is_some() && before.admin != after.admin {
        // Must have gone through the transfer process
        before.admin_transfer_deadline != 0
    } else {
        true
    };
    
    cvlr_assert!(valid);
}

// Check that roles can never be removed once set (covers all roles, not just admin)
pub fn state_transition_admin_never_zero(
    _e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    // Once roles are set, they cannot be removed (set to None)
    let admin_valid = if before.admin.is_some() { after.admin.is_some() } else { true };
    let em_admin_valid = if before.emergency_admin.is_some() { after.emergency_admin.is_some() } else { true };
    let rewards_admin_valid = if before.rewards_admin.is_some() { after.rewards_admin.is_some() } else { true };
    let operations_admin_valid = if before.operations_admin.is_some() { after.operations_admin.is_some() } else { true };
    let pause_admin_valid = if before.pause_admin.is_some() { after.pause_admin.is_some() } else { true };
    
    let valid = admin_valid && em_admin_valid && rewards_admin_valid && operations_admin_valid && pause_admin_valid;
    cvlr_assert!(valid);
}

// 
// Transfer deadlines
// 

// Check admin deadline lifecycle
pub fn state_transition_admin_deadline_lifecycle(
    e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = check_admin_deadline_lifecycle(
        e,
        before.admin_transfer_deadline,
        after.admin_transfer_deadline,
        after.future_admin,
    );
    
    cvlr_assert!(valid);
}

// Check admin deadline clear execution path (violated)
pub fn state_transition_admin_deadline_clear(
    _e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.admin_transfer_deadline != 0 
        && after.admin_transfer_deadline == 0 {
        // Transition from non-zero to 0 (apply or revert)
        after.future_admin.is_none()
    } else {
        true
    };
    
    cvlr_assert!(valid);
}

// Check emergency admin deadline lifecycle
pub fn state_transition_em_admin_deadline_lifecycle(
    e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = check_admin_deadline_lifecycle(
        e,
        before.em_admin_transfer_deadline,
        after.em_admin_transfer_deadline,
        after.future_em_admin,
    );
    
    cvlr_assert!(valid);
}

// Check admin deadline clear execution path (violated)
pub fn state_transition_em_admin_deadline_clear(
    _e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.em_admin_transfer_deadline != 0 
        && after.em_admin_transfer_deadline == 0 {
        // Transition from non-zero to 0 (apply or revert)
        after.future_em_admin.is_none()
    } else {
        true
    };
    
    cvlr_assert!(valid);
}

// 
// Future addresses
// 

// Check future admin value consistency
pub fn state_transition_future_admin_consistency(
    _e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.admin_transfer_deadline == after.admin_transfer_deadline {
        // If deadline didn't change and is non-zero, future value must remain same
        before.future_admin == after.future_admin
    } else {
        true
    };
    
    cvlr_assert!(valid);
}

// Check future emergency admin value consistency
pub fn state_transition_future_em_admin_consistency(
    _e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.em_admin_transfer_deadline == after.em_admin_transfer_deadline {
        // If deadline didn't change, future value must remain same
        before.future_em_admin == after.future_em_admin
    } else {
        true
    };
    
    cvlr_assert!(valid);
}

// 
// Emergency and upgrade
// 

// Check emergency mode effects on upgrades vs ownership transfers
pub fn state_transition_emergency_mode_behavior(
    e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.emergency_mode && 
                   before.upgrade_deadline != 0 && 
                   after.upgrade_deadline == 0 {
        // In emergency mode, upgrade can be applied immediately
        // But admin transfer still requires time delay
        if before.admin_transfer_deadline != 0 && after.admin_transfer_deadline == 0 {
            e.ledger().timestamp() >= before.admin_transfer_deadline
        } else {
            true
        }
    } else {
        true
    };
    
    cvlr_assert!(valid);
}

// Check upgrade deadline lifecycle
pub fn state_transition_upgrade_deadline_lifecycle(
    e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = check_upgrade_deadline_lifecycle(
        e,
        before.upgrade_deadline,
        after.upgrade_deadline,
        before.future_wasm,
        after.future_wasm,
        before.emergency_mode,
        after.emergency_mode,
    );
    
    cvlr_assert!(valid);
}

// Check future wasm value consistency
pub fn state_transition_future_wasm_consistency(
    _e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = if before.upgrade_deadline == after.upgrade_deadline && 
                   after.upgrade_deadline != 0 {
        // If deadline didn't change and is non-zero, future value must remain same
        before.future_wasm == after.future_wasm
    } else {
        true
    };
    
    cvlr_assert!(valid);
}