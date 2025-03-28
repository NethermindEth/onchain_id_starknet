#[starknet::component]
pub mod VerifierComponent {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use openzeppelin_access::ownable::ownable::OwnableComponent;
    use openzeppelin_access::ownable::ownable::OwnableComponent::InternalTrait as OwnableInternalTrait;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, MutableVecTrait, StorageAsPath, StoragePathEntry, StoragePointerReadAccess,
        StoragePointerWriteAccess, Vec, VecTrait,
    };
    use crate::identity::interface::ierc735::{IERC735Dispatcher, IERC735DispatcherTrait};
    use crate::identity::interface::iidentity::{IIdentityDispatcher, IIdentityDispatcherTrait};
    use crate::verifiers::interface::{
        IClaimTopicsRegistry, ITrustedIssuersRegistry, IVerifier, VerifierABI,
    };

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
        claim_topic: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicRemoved {
        #[key]
        claim_topic: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TrustedIssuerAdded {
        #[key]
        trusted_issuer: ContractAddress,
        claim_topics: Array<felt252>,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TrustedIssuerRemoved {
        #[key]
        trusted_issuer: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicsUpdated {
        #[key]
        trusted_issuer: ContractAddress,
        claim_topics: Array<felt252>,
    }

    mod Errors {
        pub const TOPIC_LENGTH_EXCEEDS_LIMIT: felt252 = 'topic lengeth should < 16';
        pub const ZERO_ADDRESS: felt252 = 'invalid argument - zero address';
        pub const NO_TOPICS: felt252 = 'no topics available';
        pub const ZERO_TOPICS: felt252 = 'topics should > 0';
        pub const ISSUER_EXIST: felt252 = 'issuer already exist';
        pub const TRUSTED_ISSUERS_EXCEEDS_LIMIT: felt252 = 'trusted issuer should < 50';
        pub const TRUSTED_ISSUER_DOES_NOT_EXIST: felt252 = 'trusted issuer does not exist';
        pub const SENDER_IS_NOT_VERIFIED: felt252 = 'sender is not verified';
        pub const TOPIC_EXIST: felt252 = 'topic exist';
    }

    #[embeddable_as(VerifierImpl)]
    pub impl Verifier<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IVerifier<ComponentState<TContractState>> {
        fn verify(self: @ComponentState<TContractState>, identity: ContractAddress) -> bool {
            let mut verified = true;
            let required_claim_topics_storage_path = self.Verifier_required_claim_topics.as_path();
            let claim_topics_to_trusted_issuers_storage_path = self
                .Verifier_claim_topics_to_trusted_issuers
                .as_path();
            if (required_claim_topics_storage_path.len() == 0) {
                return false;
            }

            for i in 0..required_claim_topics_storage_path.len() {
                let mut claim_topic = required_claim_topics_storage_path.at(i).read();

                let mut claim_ids: Array<felt252> = array![];

                let mut claim_topics_to_trusted_issuers_storage_path =
                    claim_topics_to_trusted_issuers_storage_path
                    .entry(claim_topic);
                if claim_topics_to_trusted_issuers_storage_path.len() == 0 {
                    verified = false;
                    break;
                }
                for j in 0..claim_topics_to_trusted_issuers_storage_path.len() {
                    let mut claim_issuer = claim_topics_to_trusted_issuers_storage_path
                        .at(j)
                        .read();
                    claim_ids
                        .append(
                            poseidon_hash_span(array![claim_issuer.into(), claim_topic].span()),
                        );
                }

                let mut j = 0;
                while j != claim_ids.len() {
                    let dispatcher = IERC735Dispatcher { contract_address: identity };
                    let (found_claim_topic, _, issuer, sig, data, _) = dispatcher
                        .get_claim(*claim_ids.at(j));
                    if found_claim_topic == claim_topic {
                        let dispatcher2 = IIdentityDispatcher { contract_address: issuer };
                        let _validity = dispatcher2
                            .is_claim_valid(identity, found_claim_topic, sig, data);

                        if _validity {
                            j = claim_ids.len();
                        }

                        if !_validity && j == claim_ids.len() - 1 {
                            verified = false;
                            break;
                        }
                    } else if j == claim_ids.len() - 1 {
                        verified = false;
                        break;
                    }
                    j += 1;
                }
                if !verified {
                    break;
                };
            }

            verified
        }

        fn is_claim_topic_required(
            self: @ComponentState<TContractState>, claim_topic: felt252,
        ) -> bool {
            let mut is_required = false;
            let required_claim_topics_storage_path = self.Verifier_required_claim_topics.as_path();
            for i in 0..required_claim_topics_storage_path.len() {
                if claim_topic == required_claim_topics_storage_path.at(i).read() {
                    is_required = true;
                    break;
                };
            }
            is_required
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
            let required_claim_topics_storage_path = self.Verifier_required_claim_topics.as_path();
            assert(
                required_claim_topics_storage_path.len() < 15, Errors::TOPIC_LENGTH_EXCEEDS_LIMIT,
            );

            for i in 0..required_claim_topics_storage_path.len() {
                assert(
                    required_claim_topics_storage_path.at(i).read() != claim_topic,
                    Errors::TOPIC_EXIST,
                )
            }

            required_claim_topics_storage_path.push(claim_topic);
            self.emit(ClaimTopicAdded { claim_topic });
        }

        /// TODO:  If claim topics not exist panic
        fn remove_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();
            let required_claim_topics_storage_path = self.Verifier_required_claim_topics.as_path();
            let required_claim_topics_len = required_claim_topics_storage_path.len();
            for i in 0..required_claim_topics_len {
                if claim_topic == required_claim_topics_storage_path.at(i).read() {
                    if i != required_claim_topics_len - 1 {
                        let last_element = required_claim_topics_storage_path.pop().unwrap();
                        required_claim_topics_storage_path[i].write(last_element);
                    } else {
                        required_claim_topics_storage_path.pop().unwrap();
                    }

                    self.emit(ClaimTopicRemoved { claim_topic });
                    break;
                };
            }
        }

        /// TODO: return span instead
        fn get_claim_topics(self: @ComponentState<TContractState>) -> Array<felt252> {
            let mut claim_topics = array![];

            for i in 0..self.Verifier_required_claim_topics.len() {
                claim_topics.append(self.Verifier_required_claim_topics[i].read());
            }
            claim_topics
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
            claim_topics: Array<felt252>,
        ) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();

            let trusted_issuer_claim_topics_storage_path = self
                .Verifier_trusted_issuer_claim_topics
                .as_path()
                .entry(trusted_issuer);
            let trusted_issuers_storage_path = self.Verifier_trusted_issuers.as_path();

            assert(!trusted_issuer.is_zero(), Errors::ZERO_ADDRESS);
            assert(trusted_issuer_claim_topics_storage_path.len() == 0, Errors::ISSUER_EXIST);
            assert(claim_topics.len() > 0, Errors::ZERO_TOPICS);
            assert(claim_topics.len() <= 15, Errors::TOPIC_LENGTH_EXCEEDS_LIMIT);
            assert(trusted_issuers_storage_path.len() < 50, Errors::TRUSTED_ISSUERS_EXCEEDS_LIMIT);

            trusted_issuers_storage_path.push(trusted_issuer);

            for claim_topic in claim_topics.clone() {
                self
                    .Verifier_claim_topics_to_trusted_issuers
                    .as_path()
                    .entry(claim_topic)
                    .push(trusted_issuer);
                trusted_issuer_claim_topics_storage_path.push(claim_topic);
            }
            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics })
        }

        fn remove_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress,
        ) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();
            let trusted_issuer_claim_topics_storage_path = self
                .Verifier_trusted_issuer_claim_topics
                .as_path()
                .entry(trusted_issuer);
            assert(!trusted_issuer.is_zero(), Errors::ZERO_ADDRESS);
            assert(
                trusted_issuer_claim_topics_storage_path.len() != 0,
                Errors::TRUSTED_ISSUER_DOES_NOT_EXIST,
            );
            let trusted_issuers_storage_path = self.Verifier_trusted_issuers.as_path();
            let claim_topics_to_trusted_issuers_storage_path = self
                .Verifier_claim_topics_to_trusted_issuers
                .as_path();

            /// Clear claim topics to trusted issuer for each claim issuer trusted for
            for i in 0..trusted_issuer_claim_topics_storage_path.len() {
                let mut claim_topic = trusted_issuer_claim_topics_storage_path.at(i).read();
                // get the issuer of each claim topic
                let claim_topic_trusted_issuers_storage =
                    claim_topics_to_trusted_issuers_storage_path
                    .entry(claim_topic);
                let claim_topic_trusted_issuers_len = claim_topic_trusted_issuers_storage.len();
                for j in 0..claim_topic_trusted_issuers_len {
                    //check the issuer and remove it
                    if trusted_issuer == claim_topic_trusted_issuers_storage.at(j).read() {
                        if j != claim_topic_trusted_issuers_len - 1 {
                            let last_element = claim_topic_trusted_issuers_storage.pop().unwrap();
                            claim_topic_trusted_issuers_storage.at(j).write(last_element);
                        } else {
                            claim_topic_trusted_issuers_storage.pop().unwrap();
                        }
                        break;
                    };
                };
            }

            /// Clear trusted issuer claim topics
            while trusted_issuer_claim_topics_storage_path.pop().is_some() {}

            /// Remove issuer from trusted issuers
            let trusted_issuers_len = trusted_issuers_storage_path.len();
            for i in 0..trusted_issuers_len {
                if trusted_issuer == trusted_issuers_storage_path.at(i).read() {
                    if i != trusted_issuers_len - 1 {
                        let last_element = trusted_issuers_storage_path.pop().unwrap();
                        trusted_issuers_storage_path.at(i).write(last_element)
                    } else {
                        trusted_issuers_storage_path.pop().unwrap();
                    }
                    break;
                };
            }
            self.emit(TrustedIssuerRemoved { trusted_issuer: trusted_issuer });
        }

        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>,
        ) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();
            assert(!trusted_issuer.is_zero(), Errors::ZERO_ADDRESS);
            let trusted_issuer_claim_topics_storage_path = self
                .Verifier_trusted_issuer_claim_topics
                .as_path()
                .entry(trusted_issuer);
            assert(trusted_issuer_claim_topics_storage_path.len() != 0, Errors::NO_TOPICS);
            assert(claim_topics.len() > 0, Errors::ZERO_TOPICS);
            assert(claim_topics.len() <= 15, Errors::TOPIC_LENGTH_EXCEEDS_LIMIT);

            let claim_topics_to_trusted_issuers_storage_path = self
                .Verifier_claim_topics_to_trusted_issuers
                .as_path();

            // Remove issuer from trusted issuers by claim topics list
            for i in 0..trusted_issuer_claim_topics_storage_path.len() {
                let mut claim_topic = trusted_issuer_claim_topics_storage_path.at(i).read();
                let mut trusted_issuer_for_claim_topic_storage =
                    claim_topics_to_trusted_issuers_storage_path
                    .entry(claim_topic);
                let trusted_issuer_for_claim_topic_len = trusted_issuer_for_claim_topic_storage
                    .len();
                for j in 0..trusted_issuer_for_claim_topic_len {
                    if trusted_issuer == trusted_issuer_for_claim_topic_storage.at(j).read() {
                        if j != trusted_issuer_for_claim_topic_len - 1 {
                            let last_element = trusted_issuer_for_claim_topic_storage
                                .pop()
                                .unwrap();
                            trusted_issuer_for_claim_topic_storage.at(j).write(last_element);
                        } else {
                            trusted_issuer_for_claim_topic_storage.pop().unwrap();
                        }
                        break;
                    }
                }
            }

            // Clear trusted issuer claim topics
            while trusted_issuer_claim_topics_storage_path.pop().is_some() {}

            // Registers trusted issuers claim topics and registers issuer for claim topic
            for claim_topic in claim_topics.clone() {
                trusted_issuer_claim_topics_storage_path.push(claim_topic);
                claim_topics_to_trusted_issuers_storage_path
                    .entry(claim_topic)
                    .push(trusted_issuer);
            }

            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics });
        }

        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Array<ContractAddress> {
            let mut trusted_issuers = array![];
            for i in 0..self.Verifier_trusted_issuers.len() {
                trusted_issuers.append(self.Verifier_trusted_issuers.at(i).read());
            }
            trusted_issuers
        }

        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252,
        ) -> Array<ContractAddress> {
            let mut trusted_issuers = array![];
            let trusted_issuers_for_claim_topics_storage = self
                .Verifier_claim_topics_to_trusted_issuers
                .entry(claim_topic);

            for i in 0..trusted_issuers_for_claim_topics_storage.len() {
                trusted_issuers.append(trusted_issuers_for_claim_topics_storage.at(i).read());
            }
            trusted_issuers
        }

        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress,
        ) -> bool {
            self.Verifier_trusted_issuer_claim_topics.as_path().entry(issuer).len() > 0
        }

        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress,
        ) -> Array<felt252> {
            let trusted_issuer_claim_topics_storage_path = self
                .Verifier_trusted_issuer_claim_topics
                .as_path()
                .entry(trusted_issuer);
            let claim_topics_len = trusted_issuer_claim_topics_storage_path.len();
            assert(claim_topics_len.is_non_zero(), Errors::TRUSTED_ISSUER_DOES_NOT_EXIST);

            let mut claim_topics = array![];
            for i in 0..claim_topics_len {
                claim_topics.append(trusted_issuer_claim_topics_storage_path.at(i).read());
            }
            claim_topics
        }

        fn has_claim_topic(
            self: @ComponentState<TContractState>, issuer: ContractAddress, claim_topic: felt252,
        ) -> bool {
            let mut has_claim = false;
            let trusted_issuer_claim_topics_storage_path = self
                .Verifier_trusted_issuer_claim_topics
                .entry(issuer);
            for i in 0..trusted_issuer_claim_topics_storage_path.len() {
                if claim_topic == trusted_issuer_claim_topics_storage_path.at(i).read() {
                    has_claim = true;
                    break;
                };
            }
            has_claim
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

        fn get_claim_topics(self: @ComponentState<TContractState>) -> Array<felt252> {
            ClaimTopicsRegistry::get_claim_topics(self)
        }
        // ITrustedIssuerRegistry
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>,
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
            claim_topics: Array<felt252>,
        ) {
            TrustedIssuerRegistry::update_issuer_claim_topics(
                ref self, trusted_issuer, claim_topics,
            );
        }

        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Array<ContractAddress> {
            TrustedIssuerRegistry::get_trusted_issuers(self)
        }

        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252,
        ) -> Array<ContractAddress> {
            TrustedIssuerRegistry::get_trusted_issuers_for_claim_topic(self, claim_topic)
        }

        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress,
        ) -> bool {
            TrustedIssuerRegistry::is_trusted_issuer(self, issuer)
        }

        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress,
        ) -> Array<felt252> {
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

