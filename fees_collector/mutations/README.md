
Access Control

    emergency_0 - Skip setting/clearing emergency mode in set_emergency_mode(). Vulnerability: system cannot enter emergency mode, so perpetuates any risk to the system by breaking the mitigation mechanism.

    management_0 - Negated test of is_transfer_delayed() in set_role_address(). Vulnerability: allows immediate change of critical roles.
    management_1 - Skip setting role in set_role_address(). Vulnerability: role address cannot be changed.

    storage_0 - In get_key(), give wrong key (OperationsAdmin rather than Operator) for the RewardsAdmin role. Vulnerability: extra permissions granted to RewardsAdmin and OperationsAdmin due to address storage collision.
    storage_1 - In get_future_key(), give wrong key (FutureAdmin rather than FutureEmergencyAdmin) for the EmergencyAdmin role. Vulnerability: full Admin permissons may be granted EmergencyAdminRole due to address storage collision.
    storage_2 - In get_future_deadline_key(), give wrong key (FutureAdmin rather than TransferOwnershipDeadline) for the Admin role. Vulnerability: Admin role transfer cannot be initiated, will revert with type error when checking existing deadline.

    transfer_0 - Skip ownership transfer in apply_transfer_ownership(). Vulnerability: roles cannot be changed, violating design principle.
    transfer_1 - Ignore stored deadline in get_transfer_ownership_deadline() and return 0. Vulnerability: apply_transfer_ownership() always reverts so roles cannot be changed, violating design principle.
    transfer_2 - Ignore requested deadline in put_transfer_ownership_deadline() and store 0. Vulnerability: apply_transfer_ownership() always reverts so roles cannot be changed, violating design principle.
    transfer_3 - Fail to reset deadline in revert_transfer_ownership(). Vulnerability: transfer of Admin and EmergencyAdmin cannot be canceled.
    transfer_4 - Skip reset of deadline in apply_transfer_ownership(). Vulnerability: first transfer of Admin or EmergencyAdmin role blocks all future transfers of that role.
    transfer_5 - commit_transfer_ownership() always sets a deadline in the past. Vulnerability: role changes that should be delayed can be applied immediately after being initiated.

Fees Collector

    contract_0 (public) - Removed authorization check in commit_upgrade() restricting to Admin role. Vulnerability: anyone can initiate a software update with arbitrary code.
    contract_1 (public) - Removed authorization check in apply_transfer_ownership() restricting to Admin role. Vulnerability: anyone can complete the transfer of Admin and EmergencyAdmin roles.
    contract_2 (public) - get_emergency_mode() always returns false. Vulnerability: fees_collector.get_emergency_mode() unreliable.
    contract_3 - Removed authorization check in revert_upgrade() restricting to Admin role. Vulnerability: anyone can cancel a software update.
    contract_4 - Skip setting/clearing emergency mode in set_emergency_mode(). Vulnerability: system cannot enter emergency mode, so perpetuates any risk to the system by breaking the mitigation mechanism.
    contract_5 - Disable revert_transfer_ownership(). Vulnerability: transfer of Admin and EmergencyAdmin cannot be canceled.
    contract_6 - Removed authorization check in commit_transfer_ownership() restricting to Admin role. Vulnerability: anyone can initiate transfer of Admin and EmergencyAdmin roles to an arbitrary address.
    contract_7 - Fail to store code hash in commit_upgrade(). Vulnerability: upgrades can never be completed.
    contract_8 - Disable revert_upgrade(). Vulnerability: upgrades can never be canceled.

Upgrade

    lib_0 - Upgrades always have deadline 0 in commit_upgrade(). Vulnerability: upgrades can only be completed in emergency mode.
    lib_1 - Skip setting deadline in commit_upgrade(). Vulnerability: upgrades can only be completed in emergency mode.
    lib_2 - Skip reset of deadline in apply_upgrade(). Vulnerability: any past upgrade can be applied again.