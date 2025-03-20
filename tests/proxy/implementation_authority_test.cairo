use core::num::traits::Zero;
use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
use onchain_id_starknet::proxy::implementation_authority::IdentityImplementationAuthority;
use onchain_id_starknet::proxy::interface::{
    IIdentityImplementationAuthorityDispatcher, IIdentityImplementationAuthorityDispatcherTrait,
};
use openzeppelin_access::ownable::interface::{
    IOwnableTwoStepDispatcher, IOwnableTwoStepDispatcherTrait,
};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait,
    cheat_caller_address, declare, spy_events,
};
use starknet::{ClassHash, ContractAddress};
use crate::common::setup_identity;

pub fn INITIAL_CLASS_HASH() -> ClassHash {
    'initial_class_hash'.try_into().unwrap()
}

pub fn UPDATED_CLASS_HASH() -> ClassHash {
    'updated_class_hash'.try_into().unwrap()
}

pub fn OWNER_ADDRESS() -> ContractAddress {
    'owner'.try_into().unwrap()
}

fn deploy() -> IIdentityImplementationAuthorityDispatcher {
    let implementation_authority_contract = declare("IdentityImplementationAuthority")
        .unwrap()
        .contract_class();
    let (implementation_authority_address, _) = implementation_authority_contract
        .deploy(@array![INITIAL_CLASS_HASH().into(), OWNER_ADDRESS().into()])
        .unwrap();
    IIdentityImplementationAuthorityDispatcher {
        contract_address: implementation_authority_address,
    }
}

#[test]
#[should_panic]
fn test_should_panic_when_deployment_when_class_hash_zero() {
    let implementation_authority_contract = declare("ImplementationAuthority")
        .unwrap()
        .contract_class();
    implementation_authority_contract
        .deploy(@array![Zero::zero(), OWNER_ADDRESS().into()])
        .unwrap();
}

#[test]
fn test_should_deploy_ia_with_init_class_hash_and_owner() {
    let implementation_authority = deploy();
    assert!(
        implementation_authority.get_implementation() == INITIAL_CLASS_HASH(),
        "initial class hash mismatch",
    );
    let owner = IOwnableTwoStepDispatcher {
        contract_address: implementation_authority.contract_address,
    }
        .owner();
    assert!(owner == OWNER_ADDRESS(), "owner not set correctly");
}

#[test]
#[should_panic(expected: 'Caller is not the owner')]
fn test_should_panic_when_update_implementation_when_caller_not_owner() {
    let mut implementation_authority = deploy();
    implementation_authority.update_implementation(UPDATED_CLASS_HASH());
}

#[test]
#[should_panic(expected: 'Class hash zero')]
fn test_should_panic_when_update_implementation_when_class_hash_zero() {
    let mut implementation_authority = deploy();
    cheat_caller_address(
        implementation_authority.contract_address, OWNER_ADDRESS(), CheatSpan::TargetCalls(1),
    );
    implementation_authority.update_implementation(Zero::zero());
}

#[test]
fn test_should_update_implementation() {
    let mut implementation_authority = deploy();

    let mut spy = spy_events();

    cheat_caller_address(
        implementation_authority.contract_address, OWNER_ADDRESS(), CheatSpan::TargetCalls(1),
    );
    implementation_authority.update_implementation(UPDATED_CLASS_HASH());

    assert!(implementation_authority.get_implementation() == UPDATED_CLASS_HASH());

    spy
        .assert_emitted(
            @array![
                (
                    implementation_authority.contract_address,
                    IdentityImplementationAuthority::Event::UpdatedImplementation(
                        IdentityImplementationAuthority::UpdatedImplementation {
                            new_class_hash: UPDATED_CLASS_HASH(),
                        },
                    ),
                ),
            ],
        );
}

#[test]
#[should_panic(expected: 'Implementations are identical')]
fn test_should_panic_when_upgrade_identity_when_implementations_are_identical() {
    let setup = setup_identity();

    cheat_caller_address(
        setup.alice_identity.contract_address,
        setup.accounts.alice_account.contract_address,
        CheatSpan::TargetCalls(1),
    );
    setup
        .alice_identity
        .execute(
            setup.implementation_authority.contract_address,
            selector!("upgrade_identity"),
            [].span(),
        );
}

#[test]
fn test_should_upgrade_identity() {
    let setup = setup_identity();

    let claim_issuer_class_hash = starknet::syscalls::get_class_hash_at_syscall(
        setup.claim_issuer.contract_address,
    )
        .unwrap();

    cheat_caller_address(
        setup.implementation_authority.contract_address,
        setup.accounts.owner_account.contract_address,
        CheatSpan::TargetCalls(1),
    );
    setup.implementation_authority.update_implementation(claim_issuer_class_hash);

    cheat_caller_address(
        setup.alice_identity.contract_address,
        setup.accounts.alice_account.contract_address,
        CheatSpan::TargetCalls(1),
    );
    setup
        .alice_identity
        .execute(
            setup.implementation_authority.contract_address,
            selector!("upgrade_identity"),
            [].span(),
        );

    let alice_identity_class_hash = starknet::syscalls::get_class_hash_at_syscall(
        setup.alice_identity.contract_address,
    )
        .unwrap();
    assert(alice_identity_class_hash == claim_issuer_class_hash, 'Alice identity not upgraded');
}

