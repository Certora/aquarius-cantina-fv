## Changes in the source code

All changes are made with `#[cfg(feature = "certora")]` and `#[cfg(not(feature = "certora"))]`. Some changes relate to visibility (making private items public for verification), others to mirroring storage operations into ghosts. 

## Harness functions 

`fee_collector` program extended with public harness functions allowing access to `access_control` and `upgrade` libs.

## Mirroring storage

All read/write operations are mirrored into `GHOST_STATE` structure in shared `ghost_state` crate. Initially all ghosts initialized from storage in `ghost_init.rs`. 

## Logging 

Logging of all ghost storage variables implemented in `ghost_log.rs`.  

## Parametric rule

`sanity.rs`, `state_transition.rs`, `permissions.rs` properties are implemented in parametric style rules. The structure: 
- Assume realistic timestamp
- Fill ghosts state from persistent storage
- Log all storage variables
- Fill needed params in `parametric_params.rs` to use inside parametric function
- Execute external function
- Log all storage variables again

## Type of properties

- `sanity.rs` - parametric, basic reachability of function execution paths
- `state_transition.rs` - parametric, time-delayed transitions for roles and upgrades
- `permissions.rs` - parametric, role-based access control for state changes
- `integrity.rs` - getter/setter consistency and storage key mappings
- `high_level.rs` - multi-step workflows and emergency mode behaviors

