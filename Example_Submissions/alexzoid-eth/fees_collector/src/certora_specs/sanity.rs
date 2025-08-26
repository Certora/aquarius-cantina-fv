// Sanity (reachability in at least one execution path) property

use soroban_sdk::Env;
use cvlr::cvlr_satisfy;
use crate::certora_specs::base::ParametricParams;

pub fn sanity(
    _e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {        
    call_fn();
    cvlr_satisfy!(true);
}