use crate::access::AccessControl;
use crate::errors::AccessControlError;
use crate::role::Role;
use crate::storage::StorageTrait;
use soroban_sdk::{panic_with_error, Address, Vec};
use utils::bump::bump_instance;

#[cfg(feature = "certora")]
use ghost_state::GhostState;

pub trait SingleAddressManagementTrait {
    fn get_role_safe(&self, role: &Role) -> Option<Address>;
    fn get_role(&self, role: &Role) -> Address;
    fn set_role_address(&self, role: &Role, address: &Address);
}

pub trait MultipleAddressesManagementTrait {
    fn get_role_addresses(&self, role: &Role) -> Vec<Address>;
    fn set_role_addresses(&self, role: &Role, addresses: &Vec<Address>);
}

impl SingleAddressManagementTrait for AccessControl {
    fn get_role_safe(&self, role: &Role) -> Option<Address> {
        if role.has_many_users() {
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
        }

        let key = self.get_key(role);
        bump_instance(&self.0);
        let value = self.0.storage().instance().get(&key);

        #[cfg(feature = "certora")]
        {
            let role_clone = role.clone();
            let value_clone = value.clone();
            GhostState::update(|state| {
                match role_clone {
                    Role::Admin => state.admin = value_clone,
                    Role::EmergencyAdmin => state.emergency_admin = value_clone,
                    Role::RewardsAdmin => state.rewards_admin = value_clone,
                    Role::OperationsAdmin => state.operations_admin = value_clone,
                    Role::PauseAdmin => state.pause_admin = value_clone,
                    _ => {}
                }
            });
        }
        
        value
    }

    fn get_role(&self, role: &Role) -> Address {
        match role {
            Role::Admin => {}
            _ => {
                // only admin is guaranteed, use `get_role_safe` for other roles
                panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
            }
        }

        match self.get_role_safe(role) {
            Some(address) => address,
            None => panic_with_error!(&self.0, AccessControlError::RoleNotFound),
        }
    }

    fn set_role_address(&self, role: &Role, address: &Address) {
        if role.has_many_users() {
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
        }

        // require delay if address is being replaced.
        // don't require delay if role is being set for the first time
        let addr = self.get_role_safe(role);
        if addr.is_some() && !role.is_transfer_delayed() {  // MUTANT (negation)
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
        }

        let key = self.get_key(role);
        bump_instance(&self.0);
        self.0.storage().instance().set(&key, address);

        #[cfg(feature = "certora")]
        {
            let addr_clone = address.clone();
            let role_clone = role.clone();
            GhostState::update(|state| {
                match role_clone {
                    Role::Admin => state.admin = Some(addr_clone),
                    Role::EmergencyAdmin => state.emergency_admin = Some(addr_clone),
                    Role::RewardsAdmin => state.rewards_admin = Some(addr_clone),
                    Role::OperationsAdmin => state.operations_admin = Some(addr_clone),
                    Role::PauseAdmin => state.pause_admin = Some(addr_clone),
                    _ => {}
                }
            });
        }
    }
}

impl MultipleAddressesManagementTrait for AccessControl {
    fn get_role_addresses(&self, role: &Role) -> Vec<Address> {
        if !role.has_many_users() {
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
        }

        let key = self.get_key(role);
        bump_instance(&self.0);
        let value = self.0
            .storage()
            .instance()
            .get(&key)
            .unwrap_or(Vec::new(&self.0));

        #[cfg(feature = "certora")]
        {
            let role_clone = role.clone();
            let value_clone = value.clone();
            GhostState::update(|state| {
                match role_clone {
                    Role::EmergencyPauseAdmin => state.emergency_pause_admins = value_clone,
                    _ => {}
                }
            });
        }

        value
    }

    // no delay-related code as we require it only for single addresses roles
    fn set_role_addresses(&self, role: &Role, addresses: &Vec<Address>) {
        if !role.has_many_users() || role.is_transfer_delayed() {
            panic_with_error!(&self.0, AccessControlError::BadRoleUsage);
        }

        let key = self.get_key(role);
        bump_instance(&self.0);
        self.0.storage().instance().set(&key, addresses);

        #[cfg(feature = "certora")]
        {
            let addrs_clone = addresses.clone();
            let role_clone = role.clone();
            GhostState::update(|state| {
                match role_clone {
                    Role::EmergencyPauseAdmin => state.emergency_pause_admins = addrs_clone,
                    _ => {}
                }
            });
        }
    }
}
