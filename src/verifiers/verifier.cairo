//! The `VerifierComponent` is designed to manage trusted issuers and claim topics,
//! facilitating a robust verification process for claims associated with identities. It ensures
//! that only claims issued by trusted issuers are considered valid. The main offering of this
//! component is providing a registry for claim topics and trusted issuers, which can be utilized by
//! external contracts by calling the `verify` function with an identity that must satisfy
//! constraints such as having valid claims for certain claim topics, or utilized by contracts that
//! embed this component and use `only_verified_sender` as a guard/access control to enforce
//! constraints on callers.
//!
//! # Features
//!
//! - **Trusted Issuer Management**: Implements `ERC3643::ITrustedIssuersRegistry` to allow for the
//! addition and removal of trusted issuers.
//!
//! - **Claim Topic Management**: Implements `ERC3643::IClaimTopicsRegistry`, providing mechanisms
//! to manage claim topics, such as adding, removing, and updating.
//!
//! - **Verification Process**: Implements a verification process that checks if the queried
//! identity has at least one valid claim issued by an issuer trusted by this registry for each
//! required claim topic by this component.
//!
//! # Components
//!
//! - **OwnableComponent**: Implements ownership logic, ensuring that only the owner can perform
//!   sensitive operations such as adding or removing claims and issuers.
//!
//! # Constants
//!
//! - `MAXIMUM_ALLOWED_CLAIM_TOPICS`: The maximum number of claim topics that can be registered, set
//! to 15.
//! - `MAXIMUM_ALLOWED_ISSUERS`: The maximum number of trusted issuers that can be registered, set
//! to 50.
//!
//! # Security Notice
//!
//! This component has not undergone a formal security audit and should be considered experimental.
//! Users should exercise caution when implementing or deploying this code in production
//! environments.

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

    const MAXIMUM_ALLOWED_CLAIM_TOPICS: u32 = 15;
    const MAXIMUM_ALLOWED_ISSUERS: u32 = 50;

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

    /// Emitted when a claim topic has been added to the requirement list.
    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicAdded {
        #[key]
        claim_topic: felt252,
    }

    /// Emitted when a claim topic has been removed from the requirement list.
    #[derive(Drop, starknet::Event)]
    pub struct ClaimTopicRemoved {
        #[key]
        claim_topic: felt252,
    }

    /// Emitted when an issuer is added to the trusted list.
    #[derive(Drop, starknet::Event)]
    pub struct TrustedIssuerAdded {
        #[key]
        pub trusted_issuer: ContractAddress,
        pub claim_topics: Span<felt252>,
    }

    /// Emitted when an issuer is removed from the trusted list.
    #[derive(Drop, starknet::Event)]
    pub struct TrustedIssuerRemoved {
        #[key]
        trusted_issuer: ContractAddress,
    }

    /// Emitted when the set of claim topics is changed for a given trusted issuer.
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
        pub const TRUSTED_ISSUERS_EXCEEDS_LIMIT: felt252 = 'Trusted issuers should be < 50';
        pub const TRUSTED_ISSUER_DOES_NOT_EXIST: felt252 = 'Trusted issuer does not exist';
        pub const SENDER_IS_NOT_VERIFIED: felt252 = 'Sender is not verified';
        pub const CLAIM_TOPIC_ALREADY_EXIST: felt252 = 'Topic exists';
        pub const CLAIM_TOPIC_DOES_NOT_EXIST: felt252 = 'Claim topic does not exist';
    }

    #[embeddable_as(VerifierImpl)]
    pub impl Verifier<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IVerifier<ComponentState<TContractState>> {
        /// Verifies if the given identity has at least one valid claim issued by an issuer trusted
        /// by this contract for each required claim topic.
        ///
        /// # Arguments
        ///
        /// * `identity` - `ContractAddress` representing the identity to verify.
        ///
        /// # Returns
        ///
        /// Returns `bool` indicating whether the identity is verified (true) or not (false).
        fn verify(self: @ComponentState<TContractState>, identity: ContractAddress) -> bool {
            let required_claim_topics_storage = self.Verifier_required_claim_topics.as_path();
            let claim_topics_to_trusted_issuers_storage = self
                .Verifier_claim_topics_to_trusted_issuers
                .as_path();

            if required_claim_topics_storage.len().is_zero() {
                return true;
            }
            let identity_dispatcher = IERC735Dispatcher { contract_address: identity };
            let mut required_claims_iterator = required_claim_topics_storage
                .into_iter_full_range()
                .map(|claim_storage| claim_storage.read());

            /// For each required claim topic ensures there is at least one valid claim issued by
            /// trusted issuer.
            required_claims_iterator
                .all(
                    |claim_topic| {
                        let mut claim_topics_to_trusted_issuers_storage =
                            claim_topics_to_trusted_issuers_storage
                            .entry(claim_topic);

                        if claim_topics_to_trusted_issuers_storage.len().is_zero() {
                            return false;
                        }

                        let mut claim_ids = claim_topics_to_trusted_issuers_storage
                            .into_iter_full_range()
                            .map(
                                |claim_issuer| {
                                    poseidon_hash_span(
                                        array![claim_issuer.read().into(), claim_topic].span(),
                                    )
                                },
                            )
                            .collect::<Array<_>>();

                        /// Checks if identity has at least one valid claim for topic issued by
                        /// trusted issuer
                        let mut claim_ids_iter = claim_ids.into_iter();
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

        /// Determines if a given claim topic is part of the required claim topics.
        ///
        /// # Returns
        ///
        /// A `bool` indicating whether the claim topic is required.
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
        /// Registers a claim topic.
        ///
        /// # Arguments
        ///
        /// * `claim_topic` - `felt252` representing the claim topic to register.
        ///
        /// # Requirements
        ///
        /// - Must be called by the owner.
        /// - Claim topic must not already be registered.
        /// - The number of claim topics stored by this registry must not exceed 15.
        fn add_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();
            assert(
                self.Verifier_required_claim_topics.len() < MAXIMUM_ALLOWED_CLAIM_TOPICS.into(),
                Errors::TOPIC_LENGTH_EXCEEDS_LIMIT,
            );
            let mut iterator = self.Verifier_required_claim_topics.into_iter_full_range();

            let is_topics_exist = iterator.any(|_claim_topic| _claim_topic.read() == claim_topic);
            assert(!is_topics_exist, Errors::CLAIM_TOPIC_ALREADY_EXIST);

            self.Verifier_required_claim_topics.push(claim_topic);
            self.emit(ClaimTopicAdded { claim_topic });
        }

        /// Removes a claim topic from storage.
        ///
        /// # Arguments
        ///
        /// * `claim_topic` - `felt252` representing the claim topic to remove.
        ///
        /// # Requirements
        ///
        /// - Must be called by the owner.
        /// - Claim topic must already be registered.
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

        /// Returns `Span<felt252>` representing the set of claim topics.
        ///
        /// # Returns
        ///
        /// A `Span<felt252>` containing the registered claim topics.
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
        /// Adds an issuer to the trusted list.
        ///
        /// # Arguments
        ///
        /// - `trusted_issuer` - `ContractAddress` representing the issuer to add.
        /// - `claim_topics` - `Span<felt252>` representing claim topics that the trusted issuer is
        /// trusted on.
        ///
        /// # Requirements
        ///
        /// - Only callable by the owner of the contract.
        /// - `trusted_issuer` must be non-zero.
        /// - `trusted_issuer` must not already be registered.
        /// - The length of `claim_topics` should be greater than zero and less than or equal to 15.
        /// - The number of issuers trusted by this registry must not exceed 50.
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Span<felt252>,
        ) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();

            assert(!trusted_issuer.is_zero(), Errors::ZERO_ADDRESS);
            assert(claim_topics.len().is_non_zero(), Errors::ZERO_TOPICS);
            assert(
                claim_topics.len() <= MAXIMUM_ALLOWED_CLAIM_TOPICS,
                Errors::TOPIC_LENGTH_EXCEEDS_LIMIT,
            );

            let trusted_issuer_claim_topics_storage = self
                .Verifier_trusted_issuer_claim_topics
                .entry(trusted_issuer);
            let trusted_issuers_storage = self.Verifier_trusted_issuers.as_path();

            assert(
                trusted_issuer_claim_topics_storage.len().is_zero(), Errors::ISSUER_ALREADY_EXIST,
            );

            assert(
                trusted_issuers_storage.len() < MAXIMUM_ALLOWED_ISSUERS.into(),
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

        /// Removes an issuer from the trusted list.
        ///
        /// # Arguments
        ///
        /// - `trusted_issuer` - `ContractAddress` representing the issuer to remove.
        ///
        /// # Requirements
        ///
        /// - Only callable by the owner of the contract.
        /// - `trusted_issuer` must be non-zero.
        /// - `trusted_issuer` must already be registered.
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

        /// Updates claim topics that the issuer is trusted on.
        ///
        /// # Arguments
        ///
        /// - `trusted_issuer` - `ContractAddress` representing the issuer to update claims.
        /// - `claim_topics` - `Span<felt252>` representing the new set of claim topics that the
        /// trusted issuer is trusted on.
        ///
        /// # Requirements
        ///
        /// - Only callable by the owner of the contract.
        /// - `trusted_issuer` must be non-zero.
        /// - `trusted_issuer` must already be registered.
        /// - The length of `claim_topics` should be greater than zero and less than or equal to 15.
        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Span<felt252>,
        ) {
            let ownable_comp = get_dep_component!(@self, Owner);
            ownable_comp.assert_only_owner();
            assert(!trusted_issuer.is_zero(), Errors::ZERO_ADDRESS);
            assert(claim_topics.len().is_non_zero(), Errors::ZERO_TOPICS);
            assert(
                claim_topics.len() <= MAXIMUM_ALLOWED_CLAIM_TOPICS,
                Errors::TOPIC_LENGTH_EXCEEDS_LIMIT,
            );

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

            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics });
        }

        /// Returns `Span<ContractAddress>` representing the trusted issuers.
        ///
        /// # Returns
        ///
        /// A `Span<ContractAddress>` containing the registered trusted issuers.
        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Span<ContractAddress> {
            self.Verifier_trusted_issuers.to_array().span()
        }

        /// Determines issuers trusted on a given claim topic.
        ///
        /// # Arguments
        ///
        /// * `claim_topic` - `felt252` representing the claim topic to query trusted issuers for.
        ///
        /// # Returns
        ///
        /// Returns `Span<ContractAddress>` representing the trusted issuers for the given claim
        /// topic.
        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252,
        ) -> Span<ContractAddress> {
            self.Verifier_claim_topics_to_trusted_issuers.entry(claim_topic).to_array().span()
        }

        /// Returns `bool` indicating if the `issuer` is trusted or not. True if trusted.
        ///
        /// # Arguments
        ///
        /// * `issuer` - `ContractAddress` representing the issuer to check.
        ///
        /// # Returns
        ///
        /// Returns `true` if the issuer is trusted, otherwise returns `false`.
        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress,
        ) -> bool {
            self.Verifier_trusted_issuer_claim_topics.entry(issuer).len().is_non_zero()
        }

        /// Returns `Span<felt252>` representing claim topics that the `trusted_issuer` is trusted
        /// on.
        ///
        /// # Arguments
        ///
        /// * `trusted_issuer` - `ContractAddress` representing the issuer to query.
        ///
        /// # Returns
        ///
        /// Returns a `Span<felt252>` containing the claim topics that the trusted issuer is trusted
        /// on.
        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress,
        ) -> Span<felt252> {
            let claim_topics_storage = self
                .Verifier_trusted_issuer_claim_topics
                .entry(trusted_issuer);
            assert(claim_topics_storage.len().is_non_zero(), Errors::TRUSTED_ISSUER_DOES_NOT_EXIST);

            claim_topics_storage.to_array().span()
        }

        /// Determines if a given `issuer` has a `claim_topic`.
        ///
        /// # Arguments
        ///
        /// * `issuer` - `ContractAddress` representing the issuer to check.
        /// * `claim_topic` - `felt252` representing the claim topic to check.
        ///
        /// # Returns
        ///
        /// Returns `true` if the given `issuer` has the `claim_topic`, otherwise returns `false`.
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
        /// Panics if called by any account that is not verified. Use this
        /// to restrict access to certain functions that should be called by verified senders.
        fn only_verified_sender(self: @ComponentState<TContractState>) {
            assert(
                IVerifier::verify(self, starknet::get_caller_address()),
                Errors::SENDER_IS_NOT_VERIFIED,
            );
        }
    }
}
