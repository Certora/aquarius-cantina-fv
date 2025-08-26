#![no_std]
pub mod access;
pub mod constants;
pub mod emergency;
pub mod errors;
pub mod events;
pub mod interface;
pub mod management;
pub mod role;
pub mod storage; //i: changed to public?
pub mod transfer;
pub mod utils;
use soroban_sdk::Address;
#[cfg(feature = "certora")]
pub static mut GHOST_TRANSFER_DELAYED_COUNTER: u32 = 0;
#[cfg(feature = "certora")]
pub static mut GHOST_HAS_MANY_USERS_COUNTER: u32 = 0;
#[cfg(feature = "certora")]
pub static mut GHOST_TRANSFER_DEADLINE_COUNTER: u32 = 0;
#[cfg(feature = "certora")]
pub static mut GHOST_EVENT_COUNTER: u32 = 0;
#[cfg(feature = "certora")]
pub static mut GHOST_FROM_SYMBOL_COUNTER: u32 = 0;
#[cfg(feature = "certora")]
pub static mut GHOST_GET_KEY_COUNTER: u32 = 0;
#[cfg(feature = "certora")]
pub static mut GHOST_EMERGANCY_PAUSE_ADMIN: Option<Address> = None;


