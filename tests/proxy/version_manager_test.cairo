use core::num::traits::Zero;
use onchain_id_starknet::interface::iimplementation_authority::{
    IImplementationAuthorityDispatcher, IImplementationAuthorityDispatcherTrait,
};
use onchain_id_starknet::mocks::mock_with_version_manager::{
    IMockWithVersionManagerDispatcher, IMockWithVersionManagerDispatcherTrait,
};
use onchain_id_starknet::proxy::version_manager::{
    IUpgradeableDispatcher, IUpgradeableDispatcherTrait,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, get_class_hash, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::ContractAddress;

pub fn OWNER_ADDRESS() -> ContractAddress {
    'owner'.try_into().unwrap()
}

pub fn setup_version_manager() -> (
    IImplementationAuthorityDispatcher, IMockWithVersionManagerDispatcher,
) {
    let mock_version_manager_contract = declare("MockWithVersionManager").unwrap().contract_class();
    let implementation_authority_contract = declare("ImplementationAuthority")
        .unwrap()
        .contract_class();
    let mut implementation_authority_ctor_data: Array<felt252> = array![];
    mock_version_manager_contract.class_hash.serialize(ref implementation_authority_ctor_data);
    OWNER_ADDRESS().serialize(ref implementation_authority_ctor_data);
    let (implementation_authority_address, _) = implementation_authority_contract
        .deploy(@implementation_authority_ctor_data)
        .unwrap();

    let (mock_version_manager_address, _) = mock_version_manager_contract
        .deploy(@array![implementation_authority_address.into()])
        .unwrap();
    (
        IImplementationAuthorityDispatcher { contract_address: implementation_authority_address },
        IMockWithVersionManagerDispatcher { contract_address: mock_version_manager_address },
    )
}

#[test]
#[should_panic]
fn test_initialization_should_panic_when_implementation_address_zero() {
    let mock_version_manager_contract = declare("MockWithVersionManager").unwrap().contract_class();
    mock_version_manager_contract.deploy(@array![Zero::zero()]).unwrap();
}

#[test]
fn test_should_execute_when_class_hash_matches() {
    let (_, mut mock_version_manager) = setup_version_manager();
    mock_version_manager.do_something();
}

#[test]
#[should_panic(
    expected: "Identity implementation is outdated! Trigger upgrade() function to upgrade your identity to latest version",
)]
fn test_should_panic_when_class_hash_does_not_match() {
    let (mut implementation_authority, mut mock_version_manager) = setup_version_manager();
    start_cheat_caller_address(implementation_authority.contract_address, OWNER_ADDRESS());
    implementation_authority
        .update_implementation(get_class_hash(implementation_authority.contract_address));
    stop_cheat_caller_address(implementation_authority.contract_address);
    mock_version_manager.do_something();
}

#[test]
fn test_should_upgrade_implementation() {
    let (mut implementation_authority, mut mock_version_manager) = setup_version_manager();
    start_cheat_caller_address(implementation_authority.contract_address, OWNER_ADDRESS());
    let class_hash_to_update = get_class_hash(implementation_authority.contract_address);
    implementation_authority.update_implementation(class_hash_to_update);
    stop_cheat_caller_address(implementation_authority.contract_address);
    let class_hash_pre = get_class_hash(mock_version_manager.contract_address);
    IUpgradeableDispatcher { contract_address: mock_version_manager.contract_address }.upgrade();
    let class_hash_after = get_class_hash(mock_version_manager.contract_address);
    assert!(class_hash_pre != class_hash_after, "Didnt upgrade the contract");
    assert!(class_hash_after == class_hash_to_update, "class_hash does not match");
}
