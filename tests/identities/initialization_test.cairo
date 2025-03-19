use core::num::traits::Zero;
use onchain_id_starknet::version::version::{IVersionDispatcher, IVersionDispatcherTrait, VERSION};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, mock_call};

#[test]
#[should_panic]
fn test_should_panic_when_invalid_initial_key() {
    let identity_contract = declare("Identity").unwrap().contract_class();
    let implementation_authority_address = starknet::contract_address_const::<
        'implementation_authority',
    >();
    mock_call(
        implementation_authority_address,
        selector!("get_implementation"),
        starknet::class_hash::class_hash_const::<'dummy_class_hash'>(),
        1,
    );
    identity_contract
        .deploy(@array![implementation_authority_address.into(), Zero::zero()])
        .unwrap();
}

#[test]
#[should_panic]
fn test_should_panic_when_implementation_authority_zero() {
    let identity_contract = declare("Identity").unwrap().contract_class();
    identity_contract
        .deploy(
            @array![
                Zero::zero(), starknet::contract_address_const::<'initial_management_key'>().into(),
            ],
        )
        .unwrap();
}

#[test]
fn test_should_return_version_of_the_implementation() {
    let identity_contract = declare("Identity").unwrap().contract_class();
    let implementation_authority_address = starknet::contract_address_const::<
        'implementation_authority',
    >();
    mock_call(
        implementation_authority_address,
        selector!("get_implementation"),
        starknet::class_hash::class_hash_const::<'dummy_class_hash'>(),
        1,
    );
    let (identity_address, _) = identity_contract
        .deploy(
            @array![
                implementation_authority_address.into(),
                starknet::contract_address_const::<'initial_management_key'>().into(),
            ],
        )
        .unwrap();
    let version = IVersionDispatcher { contract_address: identity_address }.version();
    assert!(version == VERSION);
}
