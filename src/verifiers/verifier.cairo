#[starknet::component]
pub mod VerifierComponent {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use openzeppelin_access::ownable::ownable::OwnableComponent;
    use openzeppelin_access::ownable::ownable::OwnableComponent::InternalTrait as OwnableInternalTrait;
    use starknet::ContractAddress;
    use starknet::storage::{
        IntoIterRange, Map, MutableVecTrait, StorageAsPath, StoragePathEntry,
        StoragePointerReadAccess, Vec, VecTrait,
    };
    use crate::identity::interface::ierc735::{IERC735Dispatcher, IERC735DispatcherTrait};
    use crate::identity::interface::iidentity::{IIdentityDispatcher, IIdentityDispatcherTrait};
    use crate::storage::vec_ext::{VecDeleteTrait, VecToArrayTrait};
    use crate::verifiers::interface::{
        IClaimTopicsRegistry, ITrustedIssuersRegistry, IVerifier, VerifierABI,
    };

    const TOPIC_LENGTH_LIMIT: u32 = 15;
    const TRUSTED_ISSERS_LENGTH_LIMIT: u32 = 50;

    #[storage]
    pub struct Storage {
        pub Verifier_required_claim_topics: Vec<felt252>,
        pub Verifier_trusted_issuers: Vec<ContractAddress>,
        pub Verifier_claim_topics_to_trusted_issuers: Map<felt252, Vec<ContractAddress>>,
        pub Verifier_trusted_issuer_claim_topics: Map<ContractAddress, Vec<felt252>>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ClaimTopicAdded: ClaimTopicAdded,
        ClaimTopicRemoved: ClaimTopicRemoved,
        TrustedIssuerAdded: TrustedIssuerAdded,
        TrustedIssuerRemoved: TrustedIssuerRemoved,
        ClaimTopicsUpdated: ClaimTopicsUpdated,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicAdded {
        #[key]
        pub claim_topic: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicRemoved {
        #[key]
        pub claim_topic: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TrustedIssuerAdded {
        #[key]
        pub trusted_issuer: ContractAddress,
        pub claim_topics: Span<felt252>,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TrustedIssuerRemoved {
        #[key]
        pub trusted_issuer: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicsUpdated {
        #[key]
        pub trusted_issuer: ContractAddress,
        pub claim_topics: Span<felt252>,
    }

    mod Errors {
        pub const TOPIC_LENGTH_EXCEEDS_LIMIT: felt252 = 'Topic length should be < 16';
        pub const ZERO_ADDRESS: felt252 = 'Invalid argument - zero address';
        pub const ZERO_TOPICS: felt252 = 'Topics should be > 0';
        pub const ISSUER_ALREADY_EXIST: felt252 = 'Issuer already exist';
        pub const TRUSTED_ISSUERS_EXCEEDS_LIMIT: felt252 = 'Trusted issuers should be < 51';
        pub const TRUSTED_ISSUER_DOES_NOT_EXIST: felt252 = 'Trusted issuer does not exist';
        pub const SENDER_IS_NOT_VERIFIED: felt252 = 'Sender is not verified';
        pub const CLAIM_TOPIC_ALREADY_EXIST: felt252 = 'Claim topic already exist';
        pub const CLAIM_TOPIC_DOES_NOT_EXIST: felt252 = 'Claim topic does not exist';
    }

    #[embeddable_as(VerifierImpl)]
    pub impl Verifier<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IVerifier<ComponentState<TContractState>> {
        fn verify(self: @ComponentState<TContractState>, identity: ContractAddress) -> bool {
            let identity_dispatcher = IERC735Dispatcher { contract_address: identity };
            let issuers_for_claim_topic_map = self
                .Verifier_claim_topics_to_trusted_issuers
                .as_path();

            let mut required_claims_iterator = self
                .Verifier_required_claim_topics
                .into_iter_full_range()
                .map(|claim_storage| claim_storage.read());

            required_claims_iterator
                .all(
                    |claim_topic| {
                        let mut claim_ids_iter = issuers_for_claim_topic_map
                            .entry(claim_topic)
                            .into_iter_full_range()
                            .map(
                                |claim_issuer| {
                                    poseidon_hash_span(
                                        array![claim_issuer.read().into(), claim_topic].span(),
                                    )
                                },
                            );

                        claim_ids_iter
                            .any(
                                |claim_id| {
                                    let (found_claim_topic, _, issuer, sig, data, _) =
                                        identity_dispatcher
                                        .get_claim(claim_id);

                                    if found_claim_topic != claim_topic {
                                        return false;
                                    }

                                    IIdentityDispatcher { contract_address: issuer }
                                        .is_claim_valid(identity, found_claim_topic, sig, data)
                                },
                            )
                    },
                )
        }

        fn is_claim_topic_required(
            self: @ComponentState<TContractState>, claim_topic: felt252,
        ) -> bool {
            let mut iterator = self.Verifier_required_claim_topics.into_iter_full_range();
            iterator.any(|_claim_topic| _claim_topic.read() == claim_topic)
        }
    }

    #[embeddable_as(ClaimTopicsRegistryImpl)]
    impl ClaimTopicsRegistry<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        impl Owner: OwnableComponent::HasComponent<TContractState>,
    > of IClaimTopicsRegistry<ComponentState<TContractState>> {
        fn add_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();
            assert(
                self.Verifier_required_claim_topics.len() < TOPIC_LENGTH_LIMIT.into(),
                Errors::TOPIC_LENGTH_EXCEEDS_LIMIT,
            );
            let mut iterator = self.Verifier_required_claim_topics.into_iter_full_range();

            let is_topics_exist = iterator.any(|_claim_topic| _claim_topic.read() == claim_topic);
            assert(!is_topics_exist, Errors::CLAIM_TOPIC_ALREADY_EXIST);

            self.Verifier_required_claim_topics.push(claim_topic);
            self.emit(ClaimTopicAdded { claim_topic });
        }

        fn remove_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();
            let mut required_claim_topics_storage = self.Verifier_required_claim_topics.as_path();
            let mut claim_topic_iterator = required_claim_topics_storage
                .into_iter_full_range()
                .enumerate();

            let (index, _) = claim_topic_iterator
                .find(
                    |iter| {
                        let (_, required_claim_topic) = iter;
                        required_claim_topic.read() == claim_topic
                    },
                )
                .expect(Errors::CLAIM_TOPIC_DOES_NOT_EXIST);

            required_claim_topics_storage.pop_swap(index.into());

            self.emit(ClaimTopicRemoved { claim_topic });
        }

        fn get_claim_topics(self: @ComponentState<TContractState>) -> Span<felt252> {
            self.Verifier_required_claim_topics.to_array().span()
        }
    }

    #[embeddable_as(TrustedIssuerRegistryImpl)]
    impl TrustedIssuerRegistry<
        TContractState,
        +HasComponent<TContractState>,
        impl Owner: OwnableComponent::HasComponent<TContractState>,
    > of ITrustedIssuersRegistry<ComponentState<TContractState>> {
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Span<felt252>,
        ) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();

            assert(!trusted_issuer.is_zero(), Errors::ZERO_ADDRESS);
            assert(claim_topics.len().is_non_zero(), Errors::ZERO_TOPICS);
            assert(claim_topics.len() <= TOPIC_LENGTH_LIMIT, Errors::TOPIC_LENGTH_EXCEEDS_LIMIT);

            let trusted_issuer_claim_topics_storage = self
                .Verifier_trusted_issuer_claim_topics
                .entry(trusted_issuer);
            let trusted_issuers_storage = self.Verifier_trusted_issuers.as_path();

            assert(
                trusted_issuer_claim_topics_storage.len().is_zero(), Errors::ISSUER_ALREADY_EXIST,
            );

            assert(
                trusted_issuers_storage.len() < TRUSTED_ISSERS_LENGTH_LIMIT.into(),
                Errors::TRUSTED_ISSUERS_EXCEEDS_LIMIT,
            );

            trusted_issuers_storage.push(trusted_issuer);

            for claim_topic in claim_topics.clone() {
                self
                    .Verifier_claim_topics_to_trusted_issuers
                    .entry(*claim_topic)
                    .push(trusted_issuer);
                trusted_issuer_claim_topics_storage.push(*claim_topic);
            }
            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics })
        }

        fn remove_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress,
        ) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();
            assert(!trusted_issuer.is_zero(), Errors::ZERO_ADDRESS);
            let trusted_issuer_claim_topics_storage = self
                .Verifier_trusted_issuer_claim_topics
                .entry(trusted_issuer);
            assert(
                trusted_issuer_claim_topics_storage.len().is_non_zero(),
                Errors::TRUSTED_ISSUER_DOES_NOT_EXIST,
            );

            let claim_topics_to_trusted_issuers_storage = self
                .Verifier_claim_topics_to_trusted_issuers
                .as_path();

            /// Clear issuer claim topics and collect them in an array
            let mut issuer_claim_topics = array![];
            for _ in 0..trusted_issuer_claim_topics_storage.len() {
                issuer_claim_topics.append(trusted_issuer_claim_topics_storage.pop().unwrap());
            }

            // Remove issuer from trusted issuers by claim topics list
            for trusted_issuer_for_claim_topic_storage in issuer_claim_topics
                .into_iter()
                .map(|topic| claim_topics_to_trusted_issuers_storage.entry(topic)) {
                for i in 0..trusted_issuer_for_claim_topic_storage.len() {
                    if trusted_issuer == trusted_issuer_for_claim_topic_storage.at(i).read() {
                        trusted_issuer_for_claim_topic_storage.pop_swap(i);
                        break;
                    }
                }
            }

            /// Remove issuer from trusted issuers
            let trusted_issuers_storage = self.Verifier_trusted_issuers.as_path();
            let mut issuer_iterator = trusted_issuers_storage.into_iter_full_range().enumerate();
            let (index, _) = issuer_iterator
                .find(|iter| {
                    let (_, storage) = iter;
                    storage.read() == trusted_issuer
                })
                .expect(Errors::TRUSTED_ISSUER_DOES_NOT_EXIST);

            trusted_issuers_storage.pop_swap(index.into());

            self.emit(TrustedIssuerRemoved { trusted_issuer: trusted_issuer });
        }

        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Span<felt252>,
        ) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();
            assert(!trusted_issuer.is_zero(), Errors::ZERO_ADDRESS);
            assert(claim_topics.len().is_non_zero(), Errors::ZERO_TOPICS);
            assert(claim_topics.len() <= TOPIC_LENGTH_LIMIT, Errors::TOPIC_LENGTH_EXCEEDS_LIMIT);

            let trusted_issuer_claim_topics_storage = self
                .Verifier_trusted_issuer_claim_topics
                .entry(trusted_issuer);
            assert(
                trusted_issuer_claim_topics_storage.len().is_non_zero(),
                Errors::TRUSTED_ISSUER_DOES_NOT_EXIST,
            );

            /// Clear issuer claim topics and collect them in an array
            let mut issuer_claim_topics = array![];
            for _ in 0..trusted_issuer_claim_topics_storage.len() {
                issuer_claim_topics.append(trusted_issuer_claim_topics_storage.pop().unwrap());
            }

            let claim_topics_to_trusted_issuers_storage = self
                .Verifier_claim_topics_to_trusted_issuers
                .as_path();

            // Remove issuer from trusted issuers by claim topics list
            for trusted_issuer_for_claim_topic_storage in issuer_claim_topics
                .into_iter()
                .map(|topic| claim_topics_to_trusted_issuers_storage.entry(topic)) {
                for i in 0..trusted_issuer_for_claim_topic_storage.len() {
                    if trusted_issuer == trusted_issuer_for_claim_topic_storage.at(i).read() {
                        trusted_issuer_for_claim_topic_storage.pop_swap(i);
                        break;
                    }
                }
            }

            // Registers trusted issuers claim topics and registers issuer for claim topic
            for claim_topic in claim_topics.clone() {
                trusted_issuer_claim_topics_storage.push(*claim_topic);
                claim_topics_to_trusted_issuers_storage.entry(*claim_topic).push(trusted_issuer);
            }

            self.emit(ClaimTopicsUpdated { trusted_issuer: trusted_issuer, claim_topics });
        }

        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Span<ContractAddress> {
            self.Verifier_trusted_issuers.to_array().span()
        }

        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252,
        ) -> Span<ContractAddress> {
            self.Verifier_claim_topics_to_trusted_issuers.entry(claim_topic).to_array().span()
        }

        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress,
        ) -> bool {
            self.Verifier_trusted_issuer_claim_topics.entry(issuer).len().is_non_zero()
        }

        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress,
        ) -> Span<felt252> {
            let claim_topics_storage = self
                .Verifier_trusted_issuer_claim_topics
                .entry(trusted_issuer);
            assert(claim_topics_storage.len().is_non_zero(), Errors::TRUSTED_ISSUER_DOES_NOT_EXIST);

            claim_topics_storage.to_array().span()
        }

        fn has_claim_topic(
            self: @ComponentState<TContractState>, issuer: ContractAddress, claim_topic: felt252,
        ) -> bool {
            let mut iterator = self
                .Verifier_trusted_issuer_claim_topics
                .entry(issuer)
                .into_iter_full_range();
            iterator.any(|topic| topic.read() == claim_topic)
        }
    }

    #[embeddable_as(VerifierABIImpl)]
    pub impl VerifierABIImplementation<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of VerifierABI<ComponentState<TContractState>> {
        // IVerify
        fn verify(self: @ComponentState<TContractState>, identity: ContractAddress) -> bool {
            Verifier::verify(self, identity)
        }

        fn is_claim_topic_required(
            self: @ComponentState<TContractState>, claim_topic: felt252,
        ) -> bool {
            Verifier::is_claim_topic_required(self, claim_topic)
        }

        // IClaimTopicsRegistry
        fn add_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            ClaimTopicsRegistry::add_claim_topic(ref self, claim_topic);
        }

        fn remove_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            ClaimTopicsRegistry::remove_claim_topic(ref self, claim_topic);
        }

        fn get_claim_topics(self: @ComponentState<TContractState>) -> Span<felt252> {
            ClaimTopicsRegistry::get_claim_topics(self)
        }
        // ITrustedIssuerRegistry
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Span<felt252>,
        ) {
            TrustedIssuerRegistry::add_trusted_issuer(ref self, trusted_issuer, claim_topics);
        }

        fn remove_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress,
        ) {
            TrustedIssuerRegistry::remove_trusted_issuer(ref self, trusted_issuer);
        }

        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Span<felt252>,
        ) {
            TrustedIssuerRegistry::update_issuer_claim_topics(
                ref self, trusted_issuer, claim_topics,
            );
        }

        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Span<ContractAddress> {
            TrustedIssuerRegistry::get_trusted_issuers(self)
        }

        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252,
        ) -> Span<ContractAddress> {
            TrustedIssuerRegistry::get_trusted_issuers_for_claim_topic(self, claim_topic)
        }

        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress,
        ) -> bool {
            TrustedIssuerRegistry::is_trusted_issuer(self, issuer)
        }

        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress,
        ) -> Span<felt252> {
            TrustedIssuerRegistry::get_trusted_issuer_claim_topics(self, trusted_issuer)
        }

        fn has_claim_topic(
            self: @ComponentState<TContractState>, issuer: ContractAddress, claim_topic: felt252,
        ) -> bool {
            TrustedIssuerRegistry::has_claim_topic(self, issuer, claim_topic)
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        fn only_verified_sender(self: @ComponentState<TContractState>) {
            assert(
                IVerifier::verify(self, starknet::get_caller_address()),
                Errors::SENDER_IS_NOT_VERIFIED,
            );
        }
    }
}
