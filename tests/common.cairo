use core::poseidon::poseidon_hash_span;
use onchain_id_starknet::factory::iid_factory::{IIdFactoryDispatcher, IIdFactoryDispatcherTrait};
use onchain_id_starknet::interface::{
    iidentity::{IdentityABIDispatcher, IdentityABIDispatcherTrait},
    iimplementation_authority::IImplementationAuthorityDispatcher,
    iclaim_issuer::{ClaimIssuerABIDispatcher, ClaimIssuerABIDispatcherTrait},
    iverifier::VerifierABIDispatcher,
};
use onchain_id_starknet::storage::structs::{Signature, StarkSignature};
use snforge_std::{
    declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
    stop_cheat_caller_address,
    signature::{
        KeyPairTrait, SignerTrait, KeyPair,
        stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
    },
};
use starknet::ContractAddress;
use starknet::account::AccountContractDispatcher;

#[derive(Drop)]
pub struct TestAccounts {
    pub owner_key: KeyPair<felt252, felt252>,
    pub owner_account: AccountContractDispatcher,
    pub alice_key: KeyPair<felt252, felt252>,
    pub alice_account: AccountContractDispatcher,
    pub bob_key: KeyPair<felt252, felt252>,
    pub bob_account: AccountContractDispatcher,
    pub carol_key: KeyPair<felt252, felt252>,
    pub carol_account: AccountContractDispatcher,
    pub david_key: KeyPair<felt252, felt252>,
    pub david_account: AccountContractDispatcher,
    pub claim_issuer_key: KeyPair<felt252, felt252>,
    pub claim_issuer_account: AccountContractDispatcher,
    pub token_owner_key: KeyPair<felt252, felt252>,
    pub token_owner_account: AccountContractDispatcher,
}

#[derive(Drop)]
pub struct FactorySetup {
    pub identity_factory: IIdFactoryDispatcher,
    pub identity_contract: starknet::ClassHash,
    pub implementation_authority: IImplementationAuthorityDispatcher,
    pub accounts: TestAccounts,
}

#[derive(Drop)]
pub struct IdentitySetup {
    pub identity_factory: IIdFactoryDispatcher,
    pub identity_contract: starknet::ClassHash,
    pub implementation_authority: IImplementationAuthorityDispatcher,
    pub claim_issuer: ClaimIssuerABIDispatcher,
    pub accounts: TestAccounts,
    pub alice_identity: IdentityABIDispatcher,
    pub bob_identity: IdentityABIDispatcher,
    pub alice_claim_666: TestClaim,
    pub token_address: ContractAddress
}

#[derive(Drop)]
pub struct VerifierSetup {
    pub identity: IdentityABIDispatcher,
    pub claim_issuer: ClaimIssuerABIDispatcher,
    pub mock_verifier: VerifierABIDispatcher,
    pub accounts: TestAccounts,
    pub alice_claim_666: TestClaim
}

#[derive(Drop)]
pub struct TestClaim {
    pub claim_id: felt252,
    pub topic: felt252,
    pub scheme: felt252,
    pub identity: ContractAddress,
    pub issuer: ContractAddress,
    pub signature: Signature,
    pub data: ByteArray,
    pub uri: ByteArray
}

pub fn setup_accounts() -> TestAccounts {
    let mock_account_contract = declare("MockAccount").unwrap().contract_class();
    // set deployer key and account
    let owner_key = KeyPairTrait::<felt252, felt252>::generate();
    let (owner_account_address, _) = mock_account_contract
        .deploy(@array![owner_key.public_key])
        .unwrap();
    let owner_account = AccountContractDispatcher { contract_address: owner_account_address };
    // set alice key and account
    let alice_key = KeyPairTrait::<felt252, felt252>::generate();
    let (alice_account_address, _) = mock_account_contract
        .deploy(@array![alice_key.public_key])
        .unwrap();
    let alice_account = AccountContractDispatcher { contract_address: alice_account_address };
    // set bob key and account
    let bob_key = KeyPairTrait::<felt252, felt252>::generate();
    let (bob_account_address, _) = mock_account_contract
        .deploy(@array![bob_key.public_key])
        .unwrap();
    let bob_account = AccountContractDispatcher { contract_address: bob_account_address };
    // set carol key and account
    let carol_key = KeyPairTrait::<felt252, felt252>::generate();
    let (carol_account_address, _) = mock_account_contract
        .deploy(@array![carol_key.public_key])
        .unwrap();
    let carol_account = AccountContractDispatcher { contract_address: carol_account_address };
    // set david key and account
    let david_key = KeyPairTrait::<felt252, felt252>::generate();
    let (david_account_address, _) = mock_account_contract
        .deploy(@array![david_key.public_key])
        .unwrap();
    let david_account = AccountContractDispatcher { contract_address: david_account_address };
    // set claim issuer key and account
    let claim_issuer_key = KeyPairTrait::<felt252, felt252>::generate();
    let (claim_issuer_account_address, _) = mock_account_contract
        .deploy(@array![claim_issuer_key.public_key])
        .unwrap();
    let claim_issuer_account = AccountContractDispatcher {
        contract_address: claim_issuer_account_address
    };
    // set token owner key and account
    let token_owner_key = KeyPairTrait::<felt252, felt252>::generate();
    let (token_owner_account_address, _) = mock_account_contract
        .deploy(@array![token_owner_key.public_key])
        .unwrap();
    let token_owner_account = AccountContractDispatcher {
        contract_address: token_owner_account_address
    };

    TestAccounts {
        owner_key,
        owner_account,
        alice_key,
        alice_account,
        bob_key,
        bob_account,
        carol_key,
        carol_account,
        david_key,
        david_account,
        claim_issuer_key,
        claim_issuer_account,
        token_owner_key,
        token_owner_account
    }
}

pub fn setup_factory() -> FactorySetup {
    let test_accounts = setup_accounts();
    // Declare Identity Contract
    let identity_contract = declare("Identity").unwrap().contract_class().class_hash;
    // Declare and Deploy ImplementationAuthority
    let implementation_authority_contract = declare("ImplementationAuthority")
        .unwrap()
        .contract_class();
    let mut implementation_authority_ctor_data: Array<felt252> = array![];
    identity_contract.serialize(ref implementation_authority_ctor_data);
    test_accounts.owner_account.contract_address.serialize(ref implementation_authority_ctor_data);
    let (implementation_authority_address, _) = implementation_authority_contract
        .deploy(@implementation_authority_ctor_data)
        .unwrap();
    let mut implementation_authority_dispatcher = IImplementationAuthorityDispatcher {
        contract_address: implementation_authority_address
    };
    // Declare and Deploy IdFactory
    let id_factory_contract = declare("IdFactory").unwrap().contract_class();
    let (id_factory_address, _) = id_factory_contract
        .deploy(
            @array![
                implementation_authority_address.into(),
                test_accounts.owner_account.contract_address.into()
            ]
        )
        .unwrap();
    let id_factory_dispatcher = IIdFactoryDispatcher { contract_address: id_factory_address };

    FactorySetup {
        identity_factory: id_factory_dispatcher,
        identity_contract: *identity_contract,
        implementation_authority: implementation_authority_dispatcher,
        accounts: test_accounts
    }
}

pub fn setup_identity() -> IdentitySetup {
    let mut factory_setup = setup_factory();

    let claim_issuer_contract = declare("ClaimIssuer").unwrap().contract_class();
    let (claim_issuer_address, _) = claim_issuer_contract
        .deploy(@array![factory_setup.accounts.claim_issuer_account.contract_address.into()])
        .unwrap();
    let claim_issuer_dispatcher = ClaimIssuerABIDispatcher {
        contract_address: claim_issuer_address
    };
    start_cheat_caller_address(
        claim_issuer_address, factory_setup.accounts.claim_issuer_account.contract_address
    );
    // register claim issuer account as claim key
    let claim_issuer_account_address_hash = poseidon_hash_span(
        array![factory_setup.accounts.claim_issuer_account.contract_address.into()].span()
    );
    claim_issuer_dispatcher.add_key(claim_issuer_account_address_hash, 3, 1);
    // register claim issuer public key as management + claim_key
    let claim_issuer_pub_key_hash = poseidon_hash_span(
        array![factory_setup.accounts.claim_issuer_key.public_key].span()
    );
    claim_issuer_dispatcher.add_key(claim_issuer_pub_key_hash, 1, 1);
    claim_issuer_dispatcher.add_key(claim_issuer_pub_key_hash, 3, 1);
    stop_cheat_caller_address(claim_issuer_address);

    start_cheat_caller_address(
        factory_setup.identity_factory.contract_address,
        factory_setup.accounts.owner_account.contract_address
    );
    factory_setup
        .identity_factory
        .create_identity(factory_setup.accounts.alice_account.contract_address, 'alice');
    stop_cheat_caller_address(factory_setup.identity_factory.contract_address);

    let alice_identity = IdentityABIDispatcher {
        contract_address: factory_setup
            .identity_factory
            .get_identity(factory_setup.accounts.alice_account.contract_address)
    };
    start_cheat_caller_address(
        alice_identity.contract_address, factory_setup.accounts.alice_account.contract_address
    );
    // register alice pub key as management key
    alice_identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.alice_key.public_key].span()), 1, 1
        );
    // register carol pub key + contract address as claim key
    alice_identity
        .add_key(
            poseidon_hash_span(
                array![factory_setup.accounts.carol_account.contract_address.into()].span()
            ),
            3,
            1
        );
    alice_identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.carol_key.public_key].span()), 3, 1
        );
    // register david pub key + contract address as action key
    alice_identity
        .add_key(
            poseidon_hash_span(
                array![factory_setup.accounts.david_account.contract_address.into()].span()
            ),
            2,
            1
        );
    alice_identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.david_key.public_key].span()), 2, 1
        );

    let claim_topic = 666_felt252;
    let issuer = claim_issuer_address;
    let claim_data = "0x00666";
    let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

    let mut serialized_claim_to_sign: Array<felt252> = array![];
    alice_identity.contract_address.serialize(ref serialized_claim_to_sign);
    claim_topic.serialize(ref serialized_claim_to_sign);
    claim_data.serialize(ref serialized_claim_to_sign);

    let hashed_claim = poseidon_hash_span(
        array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
    );

    let (r, s) = factory_setup.accounts.claim_issuer_key.sign(hashed_claim).unwrap();

    let alice_claim_666 = TestClaim {
        claim_id,
        identity: alice_identity.contract_address,
        issuer: claim_issuer_address,
        topic: claim_topic,
        scheme: 1,
        data: claim_data,
        signature: Signature::StarkSignature(
            StarkSignature { r, s, public_key: factory_setup.accounts.claim_issuer_key.public_key }
        ),
        uri: "https://example.com"
    };

    alice_identity
        .add_claim(
            alice_claim_666.topic,
            alice_claim_666.scheme,
            alice_claim_666.issuer,
            alice_claim_666.signature,
            alice_claim_666.data.clone(),
            alice_claim_666.uri.clone()
        );
    stop_cheat_caller_address(alice_identity.contract_address);

    start_cheat_caller_address(
        factory_setup.identity_factory.contract_address,
        factory_setup.accounts.owner_account.contract_address
    );
    factory_setup
        .identity_factory
        .create_identity(factory_setup.accounts.bob_account.contract_address, 'bob');
    let bob_identity = IdentityABIDispatcher {
        contract_address: factory_setup
            .identity_factory
            .get_identity(factory_setup.accounts.bob_account.contract_address)
    };

    let token_address = starknet::contract_address_const::<'token_address'>();
    factory_setup
        .identity_factory
        .create_token_identity(
            token_address,
            factory_setup.accounts.token_owner_account.contract_address,
            'token_owner'
        );
    stop_cheat_caller_address(factory_setup.identity_factory.contract_address);

    IdentitySetup {
        identity_factory: factory_setup.identity_factory,
        identity_contract: factory_setup.identity_contract,
        implementation_authority: factory_setup.implementation_authority,
        claim_issuer: claim_issuer_dispatcher,
        accounts: factory_setup.accounts,
        alice_identity,
        bob_identity,
        alice_claim_666,
        token_address
    }
}

pub fn setup_verifier() -> VerifierSetup {
    let setup = setup_identity();

    let claim_issuer_contract = declare("ClaimIssuer").unwrap().contract_class();
    let (claim_issuer_address, _) = claim_issuer_contract
        .deploy(@array![setup.accounts.claim_issuer_account.contract_address.into()])
        .unwrap();
    let claim_issuer_dispatcher = ClaimIssuerABIDispatcher {
        contract_address: claim_issuer_address
    };

    let identity_contract = declare("Identity").unwrap().contract_class();
    let (identity_address, _) = identity_contract
        .deploy(
            @array![
                setup.implementation_authority.contract_address.into(),
                setup.accounts.alice_account.contract_address.into()
            ]
        )
        .unwrap();
    let mock_verifier_contract = declare("MockVerifier").unwrap().contract_class();
    let (mock_verifier_address, _) = mock_verifier_contract
        .deploy(@array![setup.accounts.owner_account.contract_address.into()])
        .unwrap();
    let mut verifier_dispatcher = VerifierABIDispatcher { contract_address: mock_verifier_address };
    let alice_claim_666 = setup.alice_claim_666;

    VerifierSetup {
        identity: IdentityABIDispatcher { contract_address: identity_address },
        claim_issuer: claim_issuer_dispatcher,
        mock_verifier: verifier_dispatcher,
        accounts: setup.accounts,
        alice_claim_666: alice_claim_666
    }
}

pub fn get_test_claim(setup: @IdentitySetup) -> TestClaim {
    let identity = *setup.alice_identity.contract_address;
    let issuer = *setup.claim_issuer.contract_address;
    let claim_topic = 42_felt252;
    let claim_data = "0x0042";
    let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

    let mut serialized_claim_to_sign: Array<felt252> = array![];
    identity.serialize(ref serialized_claim_to_sign);
    claim_topic.serialize(ref serialized_claim_to_sign);
    claim_data.serialize(ref serialized_claim_to_sign);

    let hashed_claim = poseidon_hash_span(
        array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
    );

    let (r, s) = (*setup.accounts.claim_issuer_key).sign(hashed_claim).unwrap();
    TestClaim {
        claim_id,
        identity,
        issuer,
        topic: claim_topic,
        scheme: 1,
        data: claim_data,
        signature: Signature::StarkSignature(
            StarkSignature { r, s, public_key: *setup.accounts.claim_issuer_key.public_key }
        ),
        uri: "https://example.com"
    }
}

pub fn get_claim_issuer(
    issuer_account: AccountContractDispatcher, issuer_key: KeyPair<felt252, felt252>
) -> ContractAddress {
    let claim_issuer_contract = declare("ClaimIssuer").unwrap().contract_class();
    let factory_accounts_issuer = issuer_account.contract_address;
    let actory_accounts_issuer_public = issuer_key.public_key;
    let (claim_issuer_address, _) = claim_issuer_contract
        .deploy(@array![factory_accounts_issuer.into()])
        .unwrap();
    let claim_issuer_dispatcher = ClaimIssuerABIDispatcher {
        contract_address: claim_issuer_address
    };
    start_cheat_caller_address(claim_issuer_address, factory_accounts_issuer.into());
    // register claim issuer account as claim key
    let claim_issuer_account_address_hash = poseidon_hash_span(
        array![factory_accounts_issuer.into()].span()
    );
    claim_issuer_dispatcher.add_key(claim_issuer_account_address_hash, 3, 1);
    // register claim issuer public key as management + claim_key
    let claim_issuer_pub_key_hash = poseidon_hash_span(
        array![actory_accounts_issuer_public].span()
    );
    claim_issuer_dispatcher.add_key(claim_issuer_pub_key_hash, 1, 1);
    claim_issuer_dispatcher.add_key(claim_issuer_pub_key_hash, 3, 1);
    stop_cheat_caller_address(claim_issuer_address);

    claim_issuer_address
}

pub fn get_identity(account: AccountContractDispatcher, name: felt252) -> IdentityABIDispatcher {
    let factory_setup = setup_factory();
    start_cheat_caller_address(
        factory_setup.identity_factory.contract_address,
        factory_setup.accounts.owner_account.contract_address
    );
    factory_setup.identity_factory.create_identity(account.contract_address, name);
    stop_cheat_caller_address(factory_setup.identity_factory.contract_address);

    let identity = IdentityABIDispatcher {
        contract_address: factory_setup.identity_factory.get_identity(account.contract_address)
    };

    start_cheat_caller_address(identity.contract_address, account.contract_address);
    // register alice pub key as management key
    identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.carol_key.public_key].span()), 1, 1
        );
    // register alice pub key as management key
    identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.claim_issuer_key.public_key].span()),
            1,
            1
        );

    // register carol pub key + contract address as claim key
    identity
        .add_key(
            poseidon_hash_span(
                array![factory_setup.accounts.carol_account.contract_address.into()].span()
            ),
            3,
            1
        );
    identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.carol_key.public_key].span()), 3, 1
        );
    // register david pub key + contract address as action key
    identity
        .add_key(
            poseidon_hash_span(
                array![factory_setup.accounts.david_account.contract_address.into()].span()
            ),
            2,
            1
        );
    identity
        .add_key(
            poseidon_hash_span(array![factory_setup.accounts.david_key.public_key].span()), 2, 1
        );
    stop_cheat_caller_address(identity.contract_address);

    IdentityABIDispatcher { contract_address: identity.contract_address }
}
