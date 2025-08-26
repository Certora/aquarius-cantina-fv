# Certora Contest Report: Aquarius

## Table of contents

- [**Overview**](#overview)
    - [**About Certora**](#about-certora)
    - [**Summary**](#summary)
- [**Mutations**](#mutations)
- [**Notable Properties**](#notable-properties)
    - [**Caught Real Bugs**](#caught-real-bugs)
    - [**Caught Mutations in AccessControl Contract: management**](#caught-mutations-in-accesscontrol-contract-management)
    - [**Caught Mutations in AccessControl Contract: storage**](#caught-mutations-in-accesscontrol-contract-storage)
    - [**Caught Mutations in AccessControl Contract: transfer**](#caught-mutations-in-accesscontrol-contract-transfer)
    - [**Caught Mutations in FeesController Contract: contract**](#caught-mutations-in-feescontroller-contract-contract)
    - [**Caught Mutations in Upgrade Contract: lib**](#caught-mutations-in-upgrade-contract-lib)
- [**Disclaimer**](#disclaimer)

# Overview

## About Certora

Certora is a Web3 security company that provides industry-leading formal verification tools and smart contract audits. Certora’s flagship security product, Certora Prover, is a unique SaaS product which locates hard-to-find bugs in smart contracts or mathematically proves their absence.

A formal verification contest is a competition where members of the community mathematically validate the accuracy of smart contracts, in return for a reward offered by the sponsor based on the participants' findings and property coverage.

In the formal verification contest detailed here, contenders formally verified Aquarius smart contracts. This formal verification contest was held from 7 May, 2025 until 18 June, 2025 as part of the [audit hosted by Cantina](https://cantina.xyz/competitions/990ce947-05da-443e-b397-be38a65f0bff).

## Summary 

Code "mutations" were introduced to evaluate the quality of the specifications written by the contest participants. The mutations are described below and were made available at the end of the contest in the [updated mutations directory in the contest repository here](https://github.com/Certora/aquarius-cantina-fv/tree/main/fees_collector/mutations) along with a description of each mutation.

There were 456 properties submitted by 26 participants that successfully caught mutations. Some of those properties are included below in this report as examples of high-quality properties. Additionally, the top specifications have been added to the [contest repo](https://github.com/Certora/aquarius-cantina-fv/tree/main/Example_Submissions). You can find the final results for the competition [here](https://docs.google.com/spreadsheets/d/1fNR_A6-KsWLqw1SI9RhE_O_gi3aU8ehvWzCIYJ9MZAA/edit?gid=1970712821#gid=1970712821).

# Mutations

## Access Control Crate

### emergency.rs Mutations

**emergency_0:** 
Mutation: Skip setting/clearing emergency mode in set_emergency_mode(). 
Vulnerability: system cannot enter emergency mode, so perpetuates any risk to the system by breaking the mitigation mechanism.

### management.rs Mutations
**management_0:** 
Mutation: Negated test of is_transfer_delayed() in set_role_address(). 
Vulnerability: allows immediate change of critical roles.

**management_1:**
Mutation: Skip setting role in set_role_address(). 
Vulnerability: role address cannot be changed.

### storage.rs Mutations
**storage_0:**
Mutation: In get_key(), give wrong key (OperationsAdmin rather than Operator) for the RewardsAdmin role. 
Vulnerability: extra permissions granted to RewardsAdmin and OperationsAdmin due to address storage collision.

**storage_1:**
Mutation: In get_future_key(), give wrong key (FutureAdmin rather than FutureEmergencyAdmin) for the EmergencyAdmin role. 
Vulnerability: full Admin permissons may be granted EmergencyAdminRole due to address storage collision.

**storage_2:**
Mutation: In get_future_deadline_key(), give wrong key (FutureAdmin rather than TransferOwnershipDeadline) for the Admin role. 
Vulnerability: Admin role transfer cannot be initiated, will revert with type error when checking existing deadline.

### transfer.rs Mutations
**transfer_0:**
Mutation: Skip ownership transfer in apply_transfer_ownership(). 
Vulnerability: roles cannot be changed, violating design principle.

**transfer_1:**
Mutation: Ignore stored deadline in get_transfer_ownership_deadline() and return 0. 
Vulnerability: apply_transfer_ownership() always reverts so roles cannot be changed, violating design principle.

**transfer_2:**
Mutation: Ignore requested deadline in put_transfer_ownership_deadline() and store 0. 
Vulnerability: The numeric literal 0 is treated as default type i32 when put into storage, but get_transfer_ownership_deadline() assumes it is u64, causing all subsequent calls to it to revert. Due to this, apply_transfer_ownership() always reverts preventing ownership changes, violating design principle.

**transfer_3:**
Mutation: Fail to reset deadline in revert_transfer_ownership(). 
Vulnerability: transfer of Admin and EmergencyAdmin cannot be canceled.

**transfer_4:**
Mutation: Skip reset of deadline in apply_transfer_ownership(). 
Vulnerability: first transfer of Admin or EmergencyAdmin role blocks all future transfers of that role.

**transfer_5:**
Mutation: commit_transfer_ownership() always sets a deadline in the past. 
Vulnerability: role changes that should be delayed can be applied immediately after being initiated.

## Fees Collector Crate

### contract.rs Mutations
**contract_0 (public):**
Mutation: Removed authorization check in commit_upgrade() restricting to Admin role. 
Vulnerability: anyone can initiate a software update with arbitrary code.

**contract_1 (public):**
Mutation: Removed authorization check in apply_transfer_ownership() restricting to Admin role. 
Vulnerability: anyone can complete the transfer of Admin and EmergencyAdmin roles.

**contract_2 (public):**
Mutation: get_emergency_mode() always returns false. 
Vulnerability: fees_collector.get_emergency_mode() unreliable.

**contract_3:**
Mutation: Removed authorization check in revert_upgrade() restricting to Admin role. 
Vulnerability: anyone can cancel a software update.

**contract_4:**
Mutation: Skip setting/clearing emergency mode in set_emergency_mode(). 
Vulnerability: system cannot enter emergency mode, so perpetuates any risk to the system by breaking the mitigation mechanism.

**contract_5:**
Mutation: Disable revert_transfer_ownership(). 
Vulnerability: transfer of Admin and EmergencyAdmin cannot be canceled.

**contract_6:**
Mutation: Removed authorization check in commit_transfer_ownership() restricting to Admin role. 
Vulnerability: anyone can initiate transfer of Admin and EmergencyAdmin roles to an arbitrary address.

**contract_7:**
Mutation: Fail to store code hash in commit_upgrade(). 
Vulnerability: upgrades can never be completed.

**contract_8:**
Mutation: Disable revert_upgrade(). 
Vulnerability: upgrades can never be canceled.

## Upgrade Crate

### lib.rs Mutations
**lib_0:**
Mutation: Upgrades always have deadline 0 in commit_upgrade(). 
Vulnerability: upgrades can only be completed in emergency mode.

**lib_1:**
Mutation: Skip setting deadline in commit_upgrade(). 
Vulnerability: upgrades can only be completed in emergency mode.

**lib_2:**
Mutation: Skip reset of deadline in apply_upgrade(). 
Vulnerability: any past upgrade can be applied again.

# Notable Properties

## Caught Real Bugs

### Pending Upgrade's Code Hash Must Be Cleared Upon Upgrade or Cancellation

**Real bug caught by the following two properties:** Two participants wrote properties that caught this bug. The issue is that `commit_upgrade()` stores both a "deadline" delay timestamp and a "future_wasm" hash of the pending upgrade's code, yet the subsequent execution of `apply_upgrade()` or `revert_upgrade()` reset only the deadline and leave the code hash in storage. This creates the possibility of the admin accidentally (in emergency mode) applying an upgrade that had been cancelled or repeating an upgrade. 

*Author: PositiveSecurity*

```
fn reverted_upgrade_can_be_applied_in_emergency(e: Env, reverted_wasm_hash: BytesN<32>) {
    let admin = nondet_address();
    let emergency_admin = nondet_address();

    FeesCollector::commit_upgrade(e.clone(), admin.clone(), reverted_wasm_hash.clone());
    
    // Admin cancels previous upgrade
    FeesCollector::revert_upgrade(e.clone(), admin.clone());
    
    // EmergencyAdmin sets emergency mode
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin.clone(), true);    
    
    // Reverted wasm_hash should be never deployed
    cvlr_assert!(reverted_wasm_hash != FeesCollector::apply_upgrade(e, admin));
}
```

*Author: alexzoid-eth*

Note that the `state_transition_upgrade_deadline_lifecycle()` function below can test different `call_fn` functions. [It is processed](https://github.com/alexzoid-eth/aquarius-cantina-fv/blob/aa835937c15edabb2bee1728f58ca50d5972b00d/fees_collector/src/certora_specs/mod.rs#L64C18-L64C61) by a `parametric_rule` macro [implemented here](https://github.com/alexzoid-eth/aquarius-cantina-fv/blob/aa835937c15edabb2bee1728f58ca50d5972b00d/fees_collector/src/certora_specs/base/parametric.rs#L4) to generate a rule for each targeted function.

```
pub fn state_transition_upgrade_deadline_lifecycle(
    e: &Env,
    _params: &ParametricParams,
    call_fn: impl FnOnce()
) {
    let before = GhostState::read();
    call_fn();
    let after = GhostState::read();
    
    let valid = check_deadline_lifecycle(
        e,
        before.upgrade_deadline,
        after.upgrade_deadline,
        before.future_wasm,
        after.future_wasm,
    );
    
    cvlr_assert!(valid);
}

// Check deadline state change is valid: 0 -> timestamp -> 0
fn check_deadline_lifecycle(
    e: &Env,
    deadline_before: u64,
    deadline_after: u64,
    _future_before: Option<impl Clone>,
    future_after: Option<impl Clone>,
) -> bool {
    if deadline_before == 0 && deadline_after != 0 {
        // Transition from 0 to non-zero (commit)
        deadline_after > e.ledger().timestamp() && future_after.is_some()
    } else if deadline_before != 0 && deadline_after == 0 {
        // Transition from non-zero to 0 (apply or revert)
        future_after.is_none() // <--------------------------------------------
    } else if deadline_before != 0 && deadline_after != 0 {
        // Cannot change non-zero deadline to different non-zero value
        deadline_before == deadline_after
    } else {
        true
    }
}
```

## Caught Mutations in AccessControl Contract: management

### Role Assignment Results in Valid State Change

*Author: AsafDov*

Mutation(s) caught: management_0, management_1

```
pub fn set_role_address_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    let address_before = acc_ctrl.get_role_safe(&role);
    let address_to_set = nondet_address();

    acc_ctrl.set_role_address(&role, &address_to_set);

    let address_after = e.storage().instance().get::<DataKey, Address>(&role_key);

    match address_after{
        Some(address_after) => cvlr_assert!(
                !role.has_many_users()
            && address_after == address_to_set
            && ((address_before.is_some() && !role.is_transfer_delayed()) || (address_before.is_none()))
        ),
        None => {
            cvlr_assert!(false); // Cant set address to None
        }
    }
}
```

### Cannot Replace a Pending Role Transfer

*Author: Bhargava-krishna*

Mutation(s) caught: management_0, management_1

```
pub fn management_set_role_address_panics_for_delayed_role_replacement(e: Env) {
    let access_control = AccessControl::new(&e);
    let address1 = nondet_address();
    let address2 = nondet_address();
    let role = Role::Admin;
    
    cvlr_assume!(!role_has_many_users(&role));
    cvlr_assume!(role_is_transfer_delayed(&role));
    cvlr_assume!(address1 != address2);
    
    // Set initial role
    access_control.set_role_address(&role, &address1);
    
    // Trying to replace delayed role should panic
    access_control.set_role_address(&role, &address2);
    cvlr_assert!(false); // should not reach due to panic
}
```

## Caught Mutations in AccessControl Contract: storage

### Address Fetched for Any Role Matches Prior Set for That Role

*Author: jraynaldi3*

Mutation(s) caught: management_1, storage_0, storage_1, transfer_2

```
pub fn set_role_address_integrity(e: &Env) {
    let access_control = AccessControl::new(e);
    let input: u8 = cvlr::nondet();
    let role:Role = role_randomize(input);
    let address = nondet_address();
    access_control.set_role_address(&role, &address);
    let address_after: Option<Address> = access_control.get_role_safe(&role);

    cvlr_assert!(address == address_after.unwrap());
}
```

### Role Transfer with Delay Stores Future Address and Deadline

*Author: alexxander77*

Mutation(s) caught: storage_1, storage_2, transfer_5

```
pub fn commit_transfer_ownership_integrity(e: Env) {
    let role = nondet_role();
    let future_addr = nondet_address();
    let deadline_key = get_future_deadline_key_mock(&role.clone());
    let future_key = get_future_key_mock(&role.clone());
    let ac = AccessControl::new(&e.clone());

    let bad_role = match role {
        Role::RewardsAdmin => true,
        Role::OperationsAdmin => true,
        Role::PauseAdmin => true,
        _ => false,
    };
    let deadline_before = e.storage().instance().get::<DataKey, u64>(&deadline_key).unwrap_or(0);
    ac.commit_transfer_ownership(&role.clone(), &future_addr.clone());

    if bad_role || deadline_before != 0 {
        cvlr_assert!(false);
    } else {
        let deadline_after = e.storage().instance().get::<DataKey, u64>(&deadline_key).unwrap();
        let stored_addr = e.storage().instance().get::<DataKey, Address>(&future_key);
        cvlr_assert!(deadline_after == e.ledger().timestamp() + 3 * 86400);
        cvlr_assert!(stored_addr.is_some() && stored_addr.unwrap() == future_addr);
    }
}
```

## Caught Mutations in AccessControl Contract: transfer

### Any Role Transfer with Delay Stores Retrievable Deadline

*Author: alexzoid-eth*

Mutation(s) caught: storage_2, transfer_1, transfer_5

```
pub fn integrity_commit_transfer_deadline(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
    let deadline = e.ledger().timestamp() + ADMIN_ACTIONS_DELAY;
    FeesCollector::commit_transfer_ownership(e.clone(), admin, role_name.clone(), new_address.clone());
    let result = FeesCollector::h_get_transfer_ownership_dl(e, role_name);
    cvlr_assert!(result == deadline);
}
```

### Applying Pending Role Transfer Assigns Role to Expected Address and Resets Deadline

*Author: PositiveSecurity*

Mutation(s) caught: transfer_0, transfer_4

```
pub fn apply_transfer_ownership_correct(e: Env, role_name: &Symbol) {
    let admin = nondet_address();
    let role= Role::from_symbol(&e, role_name.clone());
    let new_admin = get_future_address(&role);
    FeesCollector::apply_transfer_ownership(e.clone(), admin, role_name.clone());
    cvlr_assert!(get_deadline(&role) == 0);
    cvlr_assert!(is_role(&new_admin, &role));
}
```

## Caught Mutations in FeesController Contract: contract

### Emergency Mode Activates and Emergency Upgrade Returns Expected Hash

*Author: dapslegend*

Mutation(s) caught: contract_2, contract_4, contract_7, emergency_0

```
pub fn emergency_mode_enables_instant_upgrade_bypass(e: Env) {
    let admin = nondet_address();
    let emergency_admin = nondet_address();
    cvlr_assume!(admin != emergency_admin);
    
    FeesCollector::init_admin(e.clone(), admin.clone());
    let acc = access_control::access::AccessControl::new(&e);
    acc.set_role_address(&access_control::role::Role::EmergencyAdmin, &emergency_admin);
    
    // Enable emergency mode
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin.clone(), true);
    cvlr_assert!(FeesCollector::get_emergency_mode(e.clone()) == true);
    
    // In emergency mode, should be able to commit and apply immediately
    let wasm = create_dummy_wasm(&e);
    FeesCollector::commit_upgrade(e.clone(), admin.clone(), wasm.clone());
    let applied_wasm = FeesCollector::apply_upgrade(e.clone(), admin.clone());
    cvlr_assert!(applied_wasm == wasm);
}
```

### Only Admin Can Execute Upgrade and Role Transfer Functions

*Author: AsafDov*

Mutation(s) caught: contract_0, contract_1, contract_3, contract_6

```
pub fn only_admin_transfers_roles_or_upgrades(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();

    // Execute any operation, then restrict to those that require Admin
    let action = nondet_func(e.clone());
    cvlr_assume!(
        action == Action::CommitTransfer
            || action == Action::ApplyTransfer
            || action == Action::RevertTransfer
            || action == Action::CommitUpgrade
            || action == Action::ApplyUpgrade
            || action == Action::RevertUpgrade
    );

    let admin: Option<Address> = e.storage().instance().get(&acc_ctrl.get_key(&Role::Admin));
    match admin {
        Some(admin) => cvlr_assert!(is_auth(admin)),    // If there is an Admin, he must be signer.
        None => cvlr_assert!(false),                    // Otherwise, the action requiring Admin should have reverted.
    }
}
```

### Upgrade and Role Transfer Functions Revert for Non-Admin

*Author: Zac369*

Mutation(s) caught: contract_0, contract_1, contract_3, contract_6

```
pub fn certain_functions_require_auth(e: Env) {
    // Randomly select and call a function that requires Admin or EmergencyAdmin role (without required role)
    let has_role = false;
    call_all_role_functions(e, has_role);

    cvlr_assert!(false);
}

```

## Caught Mutations in Upgrade Contract: lib

### Upgrade Deadline Is Set and Retrieved Correctly

*Author: alexzoid-eth*

Mutation(s) caught: contract_7, lib_0, lib_1

```
pub fn integrity_commit_upgrade_deadline(e: Env, admin: Address, new_wasm_hash: BytesN<32>) {
    let expected_deadline = e.ledger().timestamp() + ADMIN_ACTIONS_DELAY;
    FeesCollector::commit_upgrade(e.clone(), admin, new_wasm_hash);
    let deadline = FeesCollector::h_get_upgrade_deadline(e);
    cvlr_assert!(deadline == expected_deadline);
}
```

### Commit Upgrade is Restricted and Sets Retrivable Hash and Deadline

*Author: AsafDov*

Mutation(s) caught: contract_0, contract_7, lib_0, lib_1

```
pub fn commit_upgrade_integrity(e: Env) {
    let admin = get_role_safe_address(Role::Admin);
    let new_wasm = nondet_wasm();

    FeesCollector::commit_upgrade(e.clone(), nondet_address(), new_wasm.clone());

    let deadline = get_upgrade_deadline(&e);
    let future_wasm = upgrade::storage::get_future_wasm(&e).unwrap();

    match admin {
        Some(admin) => cvlr_assert!(
            future_wasm == new_wasm
                && is_auth(admin)
                && deadline == e.ledger().timestamp() + 3 * 86400
        ),
        None => cvlr_assert!(false), // Cant commit upgrade if there is no admin
    }
}
```

# Disclaimer

The Certora Prover takes a contract and a specification as input and formally proves that the contract satisfies the specification in all scenarios. Notably, the guarantees of the Certora Prover are scoped to the provided specification and the Certora Prover does not check any cases not covered by the specification. 

Certora does not provide a warranty of any kind, explicit or implied. The contents of this report should not be construed as a complete guarantee that the contract is secure in all dimensions. In no event shall Certora or any of its employees or community participants be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the results reported here. All smart contract software should be used at the sole risk and responsibility of users.


