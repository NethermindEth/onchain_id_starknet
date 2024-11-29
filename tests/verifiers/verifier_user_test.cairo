use core::poseidon::poseidon_hash_span;
use onchain_id_starknet::interface::iverifier::{VerifierABIDispatcher, VerifierABIDispatcherTrait};

use onchain_id_starknet::interface::{
    iidentity::{IdentityABIDispatcherTrait},
    iclaim_issuer::{ClaimIssuerABIDispatcher, ClaimIssuerABIDispatcherTrait},
};

use onchain_id_starknet::mocks::mock_verifier::IMockVerifierDispatcher;
use onchain_id_starknet::mocks::mock_verifier::IMockVerifierDispatcherTrait;
use onchain_id_starknet::storage::structs::{Signature, StarkSignature};
use onchain_id_starknet_tests::common::{
    setup_identity, setup_accounts, TestClaim, get_claim_issuer, get_identity, setup_factory, setup_verifier
};
use snforge_std::{
    declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
    stop_cheat_caller_address,
    signature::{
        SignerTrait,
        stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
    },
};

use starknet::ContractAddress;


#[test]
#[ignore]
#[should_panic]
fn test_should_panic_when_calling_a_verified_function_not_as_an_identity() {
    let verifier_setup = setup_verifier();
    let verifier_user = IMockVerifierDispatcher { contract_address: verifier_setup.mock_verifier.contract_address };
    //verifier_user.add_claim_topic(666_felt252);
    verifier_user.do_something();
}

#[test]
fn test_should_return_when_identity_verified() {
    let setup_accounts = setup_accounts();
    let factory_setup = setup_factory();
    let verifier_setup = setup_verifier();

    let identity = get_identity(setup_accounts.carol_account, 'carol');

    let claim_issuer = get_claim_issuer(
        factory_setup.accounts.claim_issuer_account, factory_setup.accounts.claim_issuer_key
    );

    start_cheat_caller_address(
        identity.contract_address, setup_accounts.carol_account.contract_address
    );
    let claim_topic = 666_felt252;
    let issuer = claim_issuer;
    let claim_data = "0x00666";
    let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

    let mut serialized_claim_to_sign: Array<felt252> = array![];
    identity.contract_address.serialize(ref serialized_claim_to_sign);
    claim_topic.serialize(ref serialized_claim_to_sign);
    claim_data.serialize(ref serialized_claim_to_sign);

    let hashed_claim = poseidon_hash_span(
        array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
    );

    let (r, s) = factory_setup.accounts.claim_issuer_key.sign(hashed_claim).unwrap();

    let claim_666 = TestClaim {
        claim_id,
        identity: identity.contract_address,
        issuer: claim_issuer,
        topic: claim_topic,
        scheme: 1,
        data: claim_data,
        signature: Signature::StarkSignature(
            StarkSignature { r, s, public_key: factory_setup.accounts.claim_issuer_key.public_key }
        ),
        uri: "https://example.com"
    };

    identity
        .add_claim(
            claim_666.topic,
            claim_666.scheme,
            claim_666.issuer,
            claim_666.signature,
            claim_666.data.clone(),
            claim_666.uri.clone()
        );
    stop_cheat_caller_address(identity.contract_address);

    let verifier_user = IMockVerifierDispatcher { contract_address: verifier_setup.mock_verifier.contract_address };
    let mock_verifier_address = verifier_setup.mock_verifier.contract_address;
    let to = verifier_user.contract_address;
    let selector = selector!("do_something");
    let calldata = array![];

    let mut verifier_dispatcher = VerifierABIDispatcher { contract_address: mock_verifier_address };

    start_cheat_caller_address(
        verifier_setup.mock_verifier.contract_address,
        verifier_setup.accounts.owner_account.contract_address
    );
    verifier_setup.mock_verifier.add_claim_topic(claim_666.topic);
    verifier_setup.mock_verifier.add_trusted_issuer(claim_issuer.into(), array![claim_666.topic]);
    stop_cheat_caller_address(verifier_setup.mock_verifier.contract_address);
    start_cheat_caller_address(
        identity.contract_address, setup_accounts.carol_account.contract_address
    );
    let execution_id = identity.execute(to, selector, calldata.span());
    stop_cheat_caller_address(identity.contract_address);
    assert(execution_id == 0, 'not executed')
}


#[test]
#[should_panic(expected: 'sender is not verified')]
fn test_should_return_when_identity_is_not_verified() {
    let setup_accounts = setup_accounts();
    let factory_setup = setup_factory();
    let identity = get_identity(setup_accounts.carol_account, 'carol');
    let verifier_setup = setup_verifier();

    let claim_issuer = get_claim_issuer(
        factory_setup.accounts.claim_issuer_account, factory_setup.accounts.claim_issuer_key
    );

    start_cheat_caller_address(
        identity.contract_address, setup_accounts.carol_account.contract_address
    );
    let claim_topic = 666_felt252;
    let issuer = claim_issuer;
    let claim_data = "0x00666";
    let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

    let mut serialized_claim_to_sign: Array<felt252> = array![];
    identity.contract_address.serialize(ref serialized_claim_to_sign);
    claim_topic.serialize(ref serialized_claim_to_sign);
    claim_data.serialize(ref serialized_claim_to_sign);

    let hashed_claim = poseidon_hash_span(
        array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
    );

    let (r, s) = factory_setup.accounts.claim_issuer_key.sign(hashed_claim).unwrap();

    let claim_666 = TestClaim {
        claim_id,
        identity: identity.contract_address,
        issuer: claim_issuer,
        topic: claim_topic,
        scheme: 1,
        data: claim_data,
        signature: Signature::StarkSignature(
            StarkSignature { r, s, public_key: factory_setup.accounts.claim_issuer_key.public_key }
        ),
        uri: "https://example.com"
    };

    identity
        .add_claim(
            claim_666.topic,
            claim_666.scheme,
            claim_666.issuer,
            claim_666.signature,
            claim_666.data.clone(),
            claim_666.uri.clone()
        );
    stop_cheat_caller_address(identity.contract_address);


    let verifier_user = IMockVerifierDispatcher { contract_address: verifier_setup.mock_verifier.contract_address };
    let mock_verifier_address = verifier_setup.mock_verifier.contract_address;

    let to = verifier_user.contract_address;
    let selector = selector!("do_something");
    let calldata = array![];

    let mut verifier_dispatcher = VerifierABIDispatcher { contract_address: mock_verifier_address };
    start_cheat_caller_address(
        verifier_setup.mock_verifier.contract_address,
        verifier_setup.accounts.owner_account.contract_address
    );
    verifier_dispatcher.add_claim_topic(claim_666.topic);
    verifier_dispatcher.add_trusted_issuer(claim_issuer.into(), array![claim_666.topic]);
    stop_cheat_caller_address(verifier_setup.mock_verifier.contract_address);

    let claim_issuer_dispatcher = ClaimIssuerABIDispatcher { contract_address: claim_issuer };
    //revoke claim to make not verified
    start_cheat_caller_address(claim_issuer_dispatcher.contract_address, claim_issuer);
    claim_issuer_dispatcher.revoke_claim_by_signature(claim_666.signature);
    stop_cheat_caller_address(claim_issuer_dispatcher.contract_address);

    start_cheat_caller_address(
        identity.contract_address, setup_accounts.carol_account.contract_address
    );
    let execution_id = identity.execute(to, selector, calldata.span());
    stop_cheat_caller_address(identity.contract_address);
    assert(execution_id == 0, 'not executed')
}
