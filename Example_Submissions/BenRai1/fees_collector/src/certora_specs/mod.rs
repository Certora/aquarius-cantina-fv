pub mod fee_collector_rules;
pub mod util;

use access_control::access::AccessControl;

#[cfg(feature = "certora")]
pub(crate) static mut ACCESS_CONTROL: Option<AccessControl> = None;

#[cfg(feature = "certora")]
pub static mut GHOST_BUMP_COUNTER1: i64 = 0; // Used for testing purposes in Certora



