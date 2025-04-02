use onchain_id_starknet::mocks::mock_verifier::{
    IMockVerifierDispatcher, IMockVerifierDispatcherTrait,
};
use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};
use crate::common::{setup_identity, setup_verifier};

#[test]
#[should_panic]
fn test_should_panic_when_calling_a_verified_function_not_as_an_identity() {
    let setup = setup_identity();
    let verifier = setup_verifier(
        @setup,
        [setup.alice_claim_666.topic].span(),
        [(setup.claim_issuer.contract_address, array![setup.alice_claim_666.topic])].span(),
    );

    let mock_verifier = IMockVerifierDispatcher { contract_address: verifier.contract_address };
    mock_verifier.do_something();
}

#[test]
fn test_should_return_when_identity_verified() {
    let setup = setup_identity();
    let verifier = setup_verifier(
        @setup,
        [setup.alice_claim_666.topic].span(),
        [(setup.claim_issuer.contract_address, array![setup.alice_claim_666.topic])].span(),
    );

    let mock_verifier = IMockVerifierDispatcher { contract_address: verifier.contract_address };

    start_cheat_caller_address(verifier.contract_address, setup.alice_identity.contract_address);
    mock_verifier.do_something();
    stop_cheat_caller_address(verifier.contract_address);
}

#[test]
#[should_panic(expected: 'Sender is not verified')]
fn test_should_return_false_when_identity_is_not_verified() {
    let setup = setup_identity();
    let verifier = setup_verifier(
        @setup,
        [setup.alice_claim_666.topic, 'CLAIM_TOPIC'].span(),
        [(setup.claim_issuer.contract_address, array![setup.alice_claim_666.topic, 'CLAIM_TOPIC'])]
            .span(),
    );

    let mock_verifier = IMockVerifierDispatcher { contract_address: verifier.contract_address };

    start_cheat_caller_address(verifier.contract_address, setup.alice_identity.contract_address);
    mock_verifier.do_something();
    stop_cheat_caller_address(verifier.contract_address);
}
