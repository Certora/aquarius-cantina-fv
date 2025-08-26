pub(crate) mod base;
pub(crate) mod harnesses;
pub(crate) mod sanity;
pub(crate) mod state_transition;
pub(crate) mod permissions;
pub(crate) mod integrity;
pub(crate) mod high_level;

use crate::certora_specs::base::ParametricParams;
use crate::certora_specs::base::ghost_log::ghost_log_all;

use crate::contract::FeesCollector;
use crate::interface::AdminInterface;
use access_control::interface::TransferableContract;
use upgrade::interface::UpgradeableContract;

use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

use cvlr_soroban_derive::rule;

use crate::{setup_fv, parametric_rule};

use crate::certora_specs::sanity::sanity;
use crate::certora_specs::state_transition::{
    state_transition_admin_deadline_lifecycle,
    state_transition_admin_deadline_clear,
    state_transition_em_admin_deadline_lifecycle,
    state_transition_em_admin_deadline_clear,
    state_transition_upgrade_deadline_lifecycle,
    state_transition_admin_role,
    state_transition_emergency_admin_role,
    state_transition_future_admin_consistency,
    state_transition_future_em_admin_consistency,
    state_transition_future_wasm_consistency,
    state_transition_emergency_mode_behavior,
    state_transition_admin_init_once,
    state_transition_admin_never_zero,
};

use crate::certora_specs::permissions::{
    // Role addresses
    permissions_admin_role_changes,
    permissions_other_admins_role_changes,
    // Transfer deadlines
    permissions_admin_transfer_deadline_changes,
    permissions_em_admin_transfer_deadline_changes,
    // Future addresses
    permissions_future_admin_changes,
    permissions_future_em_admin_changes,
    // Emergency and upgrade
    permissions_emergency_mode_changes,
    permissions_upgrade_deadline_changes,
    permissions_future_wasm_changes,
};

// Generate all sanity rules
parametric_rule!(sanity);

// Generate rules in parametric style for each state transition property
parametric_rule!(state_transition_admin_deadline_lifecycle);
parametric_rule!(state_transition_admin_deadline_clear);
parametric_rule!(state_transition_em_admin_deadline_lifecycle);
parametric_rule!(state_transition_em_admin_deadline_clear);
parametric_rule!(state_transition_upgrade_deadline_lifecycle);
parametric_rule!(state_transition_admin_role);
parametric_rule!(state_transition_emergency_admin_role);
parametric_rule!(state_transition_future_admin_consistency);
parametric_rule!(state_transition_future_em_admin_consistency);
parametric_rule!(state_transition_future_wasm_consistency);
parametric_rule!(state_transition_emergency_mode_behavior);
parametric_rule!(state_transition_admin_init_once);
parametric_rule!(state_transition_admin_never_zero);

// Generate rules in parametric style for permissions properties
parametric_rule!(permissions_admin_role_changes);
parametric_rule!(permissions_other_admins_role_changes);
parametric_rule!(permissions_admin_transfer_deadline_changes);
parametric_rule!(permissions_em_admin_transfer_deadline_changes);
parametric_rule!(permissions_future_admin_changes);
parametric_rule!(permissions_future_em_admin_changes);
parametric_rule!(permissions_emergency_mode_changes);
parametric_rule!(permissions_upgrade_deadline_changes);
parametric_rule!(permissions_future_wasm_changes);
