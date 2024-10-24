use starknet::ContractAddress;
#[starknet::interface]
pub trait ITrustedIssuersRegistry<TContractState> {
    fn add_trusted_issuer(
        ref self: TContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>
    );
    fn remove_trusted_issuer(ref self: TContractState, trusted_issuer: ContractAddress);
    fn update_issuer_claim_topics(
        ref self: TContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>
    );
    fn get_trusted_issuers(self: @TContractState) -> Array<ContractAddress>;
    fn get_trusted_issuers_for_claim_topic(
        self: @TContractState, claim_topic: felt252
    ) -> Array<ContractAddress>;
    fn is_trusted_issuer(self: @TContractState, issuer: ContractAddress) -> bool;
    fn get_trusted_issuer_claim_topics(
        self: @TContractState, trusted_issuer: ContractAddress
    ) -> Array<felt252>;
    fn has_claim_topic(
        self: @TContractState, trusted_issuer: ContractAddress, claim_topic: felt252
    ) -> bool;
}

#[starknet::interface]
pub trait IClaimTopicsRegistry<TContractState> {
    fn add_claim_topic(ref self: TContractState, claim_topic: felt252);
    fn remove_claim_topic(ref self: TContractState, claim_topic: felt252);
    fn get_claim_topics(self: @TContractState) -> Array<felt252>;
}

#[starknet::interface]
pub trait IVerifier<TContractState> {
    fn verify(self: @TContractState, contract_address: ContractAddress) -> bool;
    fn is_claim_topic_required(self: @TContractState, claim_topic: felt252) -> bool;
}

#[starknet::component]
pub mod VerifierComponent {
    use core::hash::{HashStateTrait, HashStateExTrait};
    use core::iter::IntoIterator;
    use core::num::traits::Zero;
    use core::poseidon::PoseidonTrait;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::interface::iclaim_issuer::IClaimIssuerDispatcher;
    use onchain_id_starknet::interface::iverifier::{
        ITrustedIssuersRegistry, IClaimTopicsRegistry, IVerifier, VerifierABI
    };
    use onchain_id_starknet::interface::{
        iclaim_issuer::IClaimIssuer, iidentity::IIdentity,
        ierc735::{IERC735Dispatcher, IERC735DispatcherTrait},
    };

    use onchain_id_starknet::storage::{
        storage::{
            StorageArrayFelt252, StorageArrayContractAddress, MutableStorageArrayTrait,
            StorageArrayTrait
        }
    };
    use openzeppelin_access::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use starknet::event::EventEmitter;
    use starknet::storage::{
        Vec, StoragePath, Mutable, VecTrait, StoragePathEntry, StorageAsPath, Map,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };
    use starknet::{get_contract_address};
    use super::ITrustedIssuersRegistry;
    use super::IVerifier;
    use super::super::super::interface::iidentity::IIdentityDispatcherTrait;

    #[storage]
    struct Storage {
        required_claim_topics: StorageArrayFelt252,
        trusted_issuers: StorageArrayContractAddress,
        claim_topics_to_trusted_issuers: Map<felt252, StorageArrayContractAddress>,
        trusted_issuer_claim_topics: Map<ContractAddress, StorageArrayFelt252>,
    }


    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ClaimTopicAdded: ClaimTopicAdded,
        ClaimTopicRemoved: ClaimTopicRemoved,
        TrustedIssuerAdded: TrustedIssuerAdded,
        TrustedIssuerRemoved: TrustedIssuerRemoved,
        ClaimTopicsUpdated: ClaimTopicsUpdated
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
    #[embeddable_as(VerifierImpl)]
    pub impl Verifier<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of IVerifier<ComponentState<TContractState>> {
        fn verify(
            self: @ComponentState<TContractState>, contract_address: ContractAddress
        ) -> bool {
            let mut verified = false;
            let required_claim_topics_storage_path = self.required_claim_topics.as_path();
            let claim_topics_to_trusted_issuers_storage_path = self
                .claim_topics_to_trusted_issuers
                .as_path();
            if (required_claim_topics_storage_path.len() == 0) {
                verified = true;
            };

            for i in 0
                ..required_claim_topics_storage_path
                    .len() {
                        let mut trusted_issuers_for_claim_topics = self
                            .get_trusted_issuers_for_claim_topic(
                                required_claim_topics_storage_path.at(i).read()
                            );
                        if trusted_issuers_for_claim_topics.len() == 0 {
                            verified = false;
                        };

                        let mut claimIds: Array<felt252> = array![];

                        let mut claim_topic = required_claim_topics_storage_path.at(i).read();
                        let mut claim_topics_to_trusted_issuers_storage_path =
                            claim_topics_to_trusted_issuers_storage_path
                            .entry(claim_topic);
                        for j in 0
                            ..claim_topics_to_trusted_issuers_storage_path
                                .len() {
                                    let mut claim_issuer =
                                        claim_topics_to_trusted_issuers_storage_path
                                        .at(j)
                                        .read();
                                    let mut serialized_data: Array<felt252> = array![];
                                    contract_address.serialize(ref serialized_data);
                                    serialized_data.append(claim_topic);
                                    serialized_data.append(claim_issuer.into());
                                    claimIds.append(poseidon_hash_span(serialized_data.span()));
                                };

                        for mut j in 0
                            ..claimIds
                                .len() {
                                    let dispatcher = IERC735Dispatcher { contract_address };
                                    let (foundClaimTopic, scheme, issuer, sig, data, uri) =
                                        dispatcher
                                        .get_claim(*claimIds.at(j));
                                    if foundClaimTopic == claim_topic {
                                        let dispatcher2 = IIdentityDispatcher {
                                            contract_address: contract_address
                                        };
                                        let _validity = dispatcher2
                                            .is_claim_valid(issuer, foundClaimTopic, sig, data);

                                        if _validity {
                                            j = claimIds.len();
                                        }

                                        if !_validity && j == claimIds.len() - 1 {
                                            verified = false;
                                        }
                                    } else {
                                        if j == claimIds.len() {
                                            verified = false;
                                        }
                                    };
                                }
                    };

            verified
        }

        fn is_claim_topic_required(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> bool {
            let mut is_required = false;
            let required_claim_topics_storage_path = self.required_claim_topics.as_path();
            for i in 0
                ..required_claim_topics_storage_path
                    .len() {
                        if claim_topic == required_claim_topics_storage_path.at(i).read() {
                            is_required = true;
                            break;
                        };
                    };
            is_required
        }
    }

    #[embeddable_as(ClaimTopicsRegistryImpl)]
    impl ClaimTopicsRegistry<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>
    > of super::IClaimTopicsRegistry<ComponentState<TContractState>> {
        fn add_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            let required_claim_topics_storage_path = self.required_claim_topics.as_path();
            assert(required_claim_topics_storage_path.len() < 15, 'can not require > 15 topics');

            for i in 0
                ..required_claim_topics_storage_path
                    .len() {
                        assert(
                            required_claim_topics_storage_path.at(i).read() != claim_topic,
                            'claim topic already exist'
                        )
                    };

            required_claim_topics_storage_path.append().write(claim_topic);
            self.emit(ClaimTopicAdded { claim_topic });
        }
        fn remove_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {
            let required_claim_topics_storage_path = self.required_claim_topics.as_path();
            for i in 0
                ..required_claim_topics_storage_path
                    .len() {
                        if claim_topic == required_claim_topics_storage_path.at(i).read() {
                            required_claim_topics_storage_path.delete(i);
                            self.emit(ClaimTopicRemoved { claim_topic })
                            break;
                        };
                    }
        }
        fn get_claim_topics(self: @ComponentState<TContractState>) -> Array<felt252> {
            self.required_claim_topics.as_path().into();
        }
    }

    #[embeddable_as(TrustedIssuerRegistryImpl)]
    impl TrustedIssuerRegistry<
        TContractState, +HasComponent<TContractState>
    > of super::ITrustedIssuersRegistry<ComponentState<TContractState>> {
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {
            let trusted_issuer_claim_topics_storage_path = self
                .trusted_issuer_claim_topics
                .as_path();
            let trusted_issuers_storage_path = self.trusted_issuers.as_path();

            assert(!trusted_issuer.is_zero(), 'invalid argument - zero address');
            assert(
                trusted_issuer_claim_topics_storage_path.entry(trusted_issuer).len() == 0,
                'trusted Issuer already exists'
            );
            assert(claim_topics.len() > 0, 'claim_topics should > 0');
            assert(claim_topics.len() <= 15, 'max claim_topics should < 16');
            assert(trusted_issuers_storage_path.len() < 50, 'max trusted_issuers should < 50');

            trusted_issuers_storage_path.append().write(trusted_issuer);

            let claim_topics_to_trusted_issuers_storage_path = self
                .claim_topics_to_trusted_issuers
                .as_path()
                .entry(claim_topic);
            let trusted_issuer_claim_topics_storage_path = trusted_issuer_claim_topics_storage_path
                .entry(trusted_issuer);
            for claim_topic in claim_topics
                .clone() {
                    trusted_issuer_claim_topics_storage_path.append().write(claim_topic);
                    claim_topics_to_trusted_issuers_storage_path.append().write(trusted_issuer);
                };
            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics })
        }
        fn remove_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) {
            let trusted_issuer_claim_topics_storage_path = self
                .trusted_issuer_claim_topics
                .as_path()
                .entry(trusted_issuer);
            assert(!trusted_issuer.is_zero(), 'invalid argument - zero address');
            assert(
                trusted_issuer_claim_topics_storage_path.entry(trusted_issuer).len() != 0,
                'trusted issuer does not exist'
            );
            let trusted_issuers_storage_path = self.trusted_issuers.as_path();
            let claim_topics_to_trusted_issuers_storage_path = self
                .claim_topics_to_trusted_issuers
                .as_path();

            for i in 0
                ..trusted_issuer_claim_topics_storage_path
                    .len() {
                        // get the issuer of each claim topic
                        for j in 0
                            ..claim_topics_to_trusted_issuers_storage_path
                                .entry(trusted_issuer_claim_topics_storage_path.at(i).read())
                                .len() {
                                    //check the issuer and remove it
                                    if trusted_issuer == claim_topics_to_trusted_issuers_storage_path
                                        .entry(
                                            trusted_issuer_claim_topics_storage_path.at(i).read()
                                        )
                                        .at(j)
                                        .read() {
                                        claim_topics_to_trusted_issuers_storage_path
                                            .entry(
                                                trusted_issuer_claim_topics_storage_path
                                                    .at(i)
                                                    .read()
                                            )
                                            .delete(j);
                                    };
                                };
                    };

            trusted_issuer_claim_topics_storage_path.clear();
            for i in 0
                ..trusted_issuers_storage_path
                    .len() {
                        if trusted_issuer == trusted_issuers_storage_path.at(i).read() {
                            trusted_issuers_storage_path.delete(i);
                            break;
                        };
                    };
            self.emit(TrustedIssuerRemoved { trusted_issuer: trusted_issuer });
        }
        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {
            let trusted_issuer_claim_topics_storage_path = self
                .trusted_issuer_claim_topics
                .as_path()
                .entry(trusted_issuer);
            assert(!trusted_issuer.is_zero(), 'invalid argument - zero address');
            assert(
                self.trusted_issuer_claim_topics.entry(trusted_issuer).len() != 0,
                'there are no topics'
            );
            assert(claim_topics.len() > 0, 'claim_topics should > 0');
            assert(claim_topics.len() <= 15, 'max claim_topics should < 16');

            let claim_topics_to_trusted_issuers_storage_path = self
                .claim_topics_to_trusted_issuers
                .as_path()
                .entry(claim_topic);
            //delete the issuer from the claim topic
            for i in 0
                ..trusted_issuer_claim_topics_storage_path
                    .len() {
                        claim_topics_to_trusted_issuers_storage_path
                            .entry(trusted_issuer_claim_topics_storage_path)
                            .clear();
                    };

            //delete the claim topic from issuer
            trusted_issuer_claim_topics_storage_path.clear();

            //add the new claim topics to the trusted issuers and vise versa
            for claim_topic in claim_topics
                .clone() {
                    trusted_issuer_claim_topics_storage_path.append().write(claim_topic);
                    claim_topics_to_trusted_issuers_storage_path.append().write(trusted_issuer);
                };
            self.emit(TrustedIssuerAdded { trusted_issuer: trusted_issuer, claim_topics });
        }
        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Array<ContractAddress> {
            self.trusted_issuers.as_path().into();
        }
        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> Array<ContractAddress> {
            let mut issuers_with_topic = ArrayTrait::<ContractAddress>::new();
            let claim_topics_to_trusted_issuers_storage_path = self
                .claim_topics_to_trusted_issuers
                .as_path()
                .entry(claim_topic);

            claim_topics_to_trusted_issuers_storage_path.into();
        }
        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress
        ) -> bool {
            let trusted_issuers_storage_path = self.trusted_issuers.as_path();
            let mut is_trusted = false;

            if self.trusted_issuer_claim_topics.as_path().entry(issuer).len() > 0 {
                is_trusted = true;
            }

            is_trusted
        }
        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) -> Array<felt252> {
            let trusted_issuer_claim_topics_storage_path = self
                .trusted_issuer_claim_topics
                .as_path();
            assert(
                trusted_issuer_claim_topics_storage_path.entry(trusted_issuer).len() != 0,
                'trusted issuer does not exist'
            );
            trusted_issuer_claim_topics_storage_path.entry(trusted_issuer).into();
        }
        fn has_claim_topic(
            self: @ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topic: felt252
        ) -> bool {
            let trusted_issuer_claim_topics_storage_path = self
                .trusted_issuer_claim_topics
                .as_path();
            let mut has_claim = false;
            let trusted_issuer_claim_topics_storage_path = trusted_issuer_claim_topics_storage_path
                .entry(trusted_issuer);
            for i in 0
                ..trusted_issuer_claim_topics_storage_path
                    .len() {
                        if claim_topic == trusted_issuer_claim_topics_storage_path.at(i).read() {
                            has_claim = true;
                            break;
                        };
                    };
            has_claim
        }
    }

    #[embeddable_as(ClaimTopicsRegistryImpl)]
    pub impl ClaimTopicsRegistry<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of IClaimTopicsRegistry<ComponentState<TContractState>> {
        fn add_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {}
        fn remove_claim_topic(ref self: ComponentState<TContractState>, claim_topic: felt252) {}
        fn get_claim_topics(self: @ComponentState<TContractState>) -> Array<felt252> {
            array![]
        }
    }

    #[embeddable_as(TrustedIssuerRegistryImpl)]
    pub impl TrustedIssuerRegistry<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of ITrustedIssuersRegistry<ComponentState<TContractState>> {
        fn add_trusted_issuer(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {}
        fn remove_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) {}
        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {}
        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Array<ContractAddress> {
            array![]
        }
        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> Array<ContractAddress> {
            array![]
        }
        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress
        ) -> bool {
            true
        }
        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) -> Array<felt252> {
            array![]
        }
        fn has_claim_topic(
            self: @ComponentState<TContractState>, issuer: ContractAddress, claim_topic: felt252
        ) -> bool {
            true
        }
    }

    #[embeddable_as(VerifierABIImpl)]
    pub impl VerifierABIImplementation<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of VerifierABI<ComponentState<TContractState>> {
        // IVerify
        fn verify(self: @ComponentState<TContractState>, identity: ContractAddress) -> bool {
            Verifier::verify(self, identity)
        }

        fn is_claim_topic_required(
            self: @ComponentState<TContractState>, claim_topic: felt252
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
            claim_topics: Array<felt252>
        ) {
            TrustedIssuerRegistry::add_trusted_issuer(ref self, trusted_issuer, claim_topics);
        }

        fn remove_trusted_issuer(
            ref self: ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) {
            TrustedIssuerRegistry::remove_trusted_issuer(ref self, trusted_issuer);
        }

        fn update_issuer_claim_topics(
            ref self: ComponentState<TContractState>,
            trusted_issuer: ContractAddress,
            claim_topics: Array<felt252>
        ) {
            TrustedIssuerRegistry::update_issuer_claim_topics(
                ref self, trusted_issuer, claim_topics
            );
        }

        fn get_trusted_issuers(self: @ComponentState<TContractState>) -> Array<ContractAddress> {
            TrustedIssuerRegistry::get_trusted_issuers(self)
        }

        fn get_trusted_issuers_for_claim_topic(
            self: @ComponentState<TContractState>, claim_topic: felt252
        ) -> Array<ContractAddress> {
            TrustedIssuerRegistry::get_trusted_issuers_for_claim_topic(self, claim_topic)
        }

        fn is_trusted_issuer(
            self: @ComponentState<TContractState>, issuer: ContractAddress
        ) -> bool {
            TrustedIssuerRegistry::is_trusted_issuer(self, issuer)
        }

        fn get_trusted_issuer_claim_topics(
            self: @ComponentState<TContractState>, trusted_issuer: ContractAddress
        ) -> Array<felt252> {
            TrustedIssuerRegistry::get_trusted_issuer_claim_topics(self, trusted_issuer)
        }

        fn has_claim_topic(
            self: @ComponentState<TContractState>, issuer: ContractAddress, claim_topic: felt252
        ) -> bool {
            TrustedIssuerRegistry::has_claim_topic(self, issuer, claim_topic)
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +OwnableComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of InternalTrait<TContractState> {
        fn only_verified_sender(self: @ComponentState<TContractState>) {
            assert(self.verify(get_caller_address()), 'sender is not verified');
        }
    }
}

