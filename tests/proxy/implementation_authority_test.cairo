use core::num::traits::Zero;
use onchain_id_starknet::proxy::implementation_authority::ImplementationAuthority;
use onchain_id_starknet::proxy::interface::{
    IImplementationAuthorityDispatcher, IImplementationAuthorityDispatcherTrait,
};
use openzeppelin_access::ownable::interface::{
    IOwnableTwoStepDispatcher, IOwnableTwoStepDispatcherTrait,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, spy_events,
    start_cheat_caller_address, stop_cheat_caller_address,
};
use starknet::{ClassHash, ContractAddress};

pub fn INITIAL_CLASS_HASH() -> ClassHash {
    'initial_class_hash'.try_into().unwrap()
}

pub fn UPDATED_CLASS_HASH() -> ClassHash {
    'updated_class_hash'.try_into().unwrap()
}

pub fn OWNER_ADDRESS() -> ContractAddress {
    'owner'.try_into().unwrap()
}

fn deploy() -> IImplementationAuthorityDispatcher {
    let implementation_authority_contract = declare("ImplementationAuthority")
        .unwrap()
        .contract_class();
    let (implementation_authority_address, _) = implementation_authority_contract
        .deploy(@array![INITIAL_CLASS_HASH().into(), OWNER_ADDRESS().into()])
        .unwrap();
    IImplementationAuthorityDispatcher { contract_address: implementation_authority_address }
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
#[should_panic(expected: 'class hash zero')]
fn test_should_panic_when_update_implementation_when_class_hash_zero() {
    let mut implementation_authority = deploy();
    start_cheat_caller_address(implementation_authority.contract_address, OWNER_ADDRESS());
    implementation_authority.update_implementation(Zero::zero());
    stop_cheat_caller_address(implementation_authority.contract_address);
}

#[test]
fn test_should_update_implementation() {
    let mut implementation_authority = deploy();

    let mut spy = spy_events();

    start_cheat_caller_address(implementation_authority.contract_address, OWNER_ADDRESS());
    implementation_authority.update_implementation(UPDATED_CLASS_HASH());
    stop_cheat_caller_address(implementation_authority.contract_address);

    assert!(implementation_authority.get_implementation() == UPDATED_CLASS_HASH());

    spy
        .assert_emitted(
            @array![
                (
                    implementation_authority.contract_address,
                    ImplementationAuthority::Event::UpdatedImplementation(
                        ImplementationAuthority::UpdatedImplementation {
                            new_class_hash: UPDATED_CLASS_HASH(),
                        },
                    ),
                ),
            ],
        );
}

