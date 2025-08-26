pub mod fee_collector_rules;
pub mod util;
pub mod utils_ext;
pub mod access_control_rules;

use access_control::access::AccessControl;

#[cfg(feature = "certora")]
pub(crate) static mut ACCESS_CONTROL: Option<AccessControl> = None;