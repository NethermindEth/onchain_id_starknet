use core::num::traits::Zero;
use core::poseidon::poseidon_hash_span;
use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;

use onchain_id_starknet::interface::{
    iidentity::{IdentityABIDispatcher, IdentityABIDispatcherTrait},
    iimplementation_authority::IImplementationAuthorityDispatcher,
    iclaim_issuer::{ClaimIssuerABIDispatcher, ClaimIssuerABIDispatcherTrait},
};

use onchain_id_starknet::interface::{ierc734};
use onchain_id_starknet::mocks::mock_simple_storage::ISimpleStorageDispatcher;
use onchain_id_starknet::mocks::mock_verifier::IMockVerifierDispatcher;
use onchain_id_starknet::mocks::mock_verifier::IMockVerifierDispatcherTrait;
use onchain_id_starknet::storage::structs::{Signature, StarkSignature};
use onchain_id_starknet_tests::common::{
    setup_verifier, setup_identity, setup_factory, TestClaim, get_test_claim
};

use snforge_std::{
    declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address, spy_events,
    EventSpyAssertionsTrait, stop_cheat_caller_address,
    signature::{
        KeyPairTrait, SignerTrait, KeyPair,
        stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
    },
};

use starknet::ContractAddress;
use starknet::account::AccountContractDispatcher;

fn deploy_verifier(contract_address: ContractAddress) -> IMockVerifierDispatcher {
    let mock_verifier_contract = declare("MockVerifier").unwrap().contract_class();
    let (mock_verifier_address, _) = mock_verifier_contract
        .deploy(@array![contract_address.into()])
        .unwrap();
    IMockVerifierDispatcher { contract_address: mock_verifier_address }
}

#[test]
#[should_panic]
fn test_should_panic_when_calling_a_verified_function_not_as_an_identity() {
    let setup = setup_identity();
    let verifier_user = deploy_verifier(setup.alice_identity.contract_address);
    verifier_user.do_something();
}

#[test]
fn test_should_return_when_identity_verified() {
    let setup = setup_identity();
    let setup_verifier = setup_verifier();
    let verifier_user = deploy_verifier(setup.alice_identity.contract_address);
    let to = verifier_user.contract_address;
    let selector = selector!("do_something");
    let calldata = array![];

    //add the issuer as trusted
    start_cheat_caller_address(
        setup_verifier.mock_verifier.contract_address,
        setup_verifier.accounts.owner_account.contract_address
    );
    setup_verifier
        .mock_verifier
        .add_trusted_issuer(
            setup.claim_issuer.contract_address.into(), array![setup.alice_claim_666.topic]
        );
    stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

    start_cheat_caller_address(
        setup.alice_identity.contract_address,
        setup_verifier.accounts.owner_account.contract_address
    );
    let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
    stop_cheat_caller_address(setup.alice_identity.contract_address);
    assert(execution_id == 0, 'not executed')
}

#[test]
#[should_panic(expected: 'sender is not verified')]
fn test_should_return_when_identity_is_not_verified() {
    let setup = setup_identity();
    let setup_verifier = setup_verifier();

    let setup = setup_identity();
    let verifier_user = deploy_verifier(setup.alice_identity.contract_address);

    let to = verifier_user.contract_address;
    let selector = selector!("do_something");
    let calldata = array![];

    //add the issuer as trusted
    start_cheat_caller_address(
        setup_verifier.mock_verifier.contract_address,
        setup_verifier.accounts.owner_account.contract_address
    );
    setup_verifier
        .mock_verifier
        .add_trusted_issuer(
            setup.claim_issuer.contract_address.into(), array![setup.alice_claim_666.topic]
        );
    stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

    //revoke the signature so that it becomes invalid
    start_cheat_caller_address(
        setup.claim_issuer.contract_address, setup.accounts.claim_issuer_account.contract_address
    );
    setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
    stop_cheat_caller_address(setup.claim_issuer.contract_address);

    start_cheat_caller_address(
        setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address
    );
    let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
    stop_cheat_caller_address(setup.alice_identity.contract_address);
}
