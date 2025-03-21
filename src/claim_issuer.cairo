#[starknet::contract]
pub mod ClaimIssuer {
    use onchain_id_starknet::identity_component::IdentityComponent;
    use onchain_id_starknet::interface::iclaim_issuer::IClaimIssuer;
    use onchain_id_starknet::interface::ierc735::{IERC735Dispatcher, IERC735DispatcherTrait};
    use onchain_id_starknet::interface::iidentity::IIdentity;
    use onchain_id_starknet::version::version;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };

    component!(path: IdentityComponent, storage: identity, event: IdentityEvent);

    #[abi(embed_v0)]
    impl ERC734Impl = IdentityComponent::ERC734Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC735Impl = IdentityComponent::ERC735Impl<ContractState>;
    impl IdentityInternalImpl = IdentityComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl VersionImpl = version::VersionImpl<ContractState>;

    #[storage]
    struct Storage {
        revoked_claims: Map<felt252, bool>,
        #[substorage(v0)]
        identity: IdentityComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ClaimRevoked: ClaimRevoked,
        #[flat]
        IdentityEvent: IdentityComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimRevoked {
        #[key]
        pub signature: Span<felt252>,
    }

    pub mod Errors {
        pub const CLAIM_ALREADY_REVOKED: felt252 = 'Claim already revoked';
    }

    #[constructor]
    fn constructor(ref self: ContractState, initial_management_key: ContractAddress) {
        self.identity.initialize(initial_management_key);
    }

    #[abi(embed_v0)]
    impl ClaimIssuerImpl of IClaimIssuer<ContractState> {
        fn revoke_claim_by_signature(ref self: ContractState, signature: Span<felt252>) {
            self.identity.only_manager();
            self._revoke_claim_by_signature(signature);
        }

        // NOTE: Deprecated - see
        // {https://docs.onchainid.com/docs/developers/contracts/claim-issuer#revocation-of-a-claim}
        fn revoke_claim(
            ref self: ContractState, claim_id: felt252, identity: ContractAddress,
        ) -> bool {
            self.identity.only_manager();
            let (_, _, _, signature, _, _) = IERC735Dispatcher { contract_address: identity }
                .get_claim(claim_id);
            self._revoke_claim_by_signature(signature);
            true
        }

        fn is_claim_revoked(self: @ContractState, signature: Span<felt252>) -> bool {
            let sig_hash = core::poseidon::poseidon_hash_span(signature);
            self.revoked_claims.entry(sig_hash).read()
        }
    }

    #[abi(embed_v0)]
    impl IdentityImpl of IIdentity<ContractState> {
        fn is_claim_valid(
            self: @ContractState,
            identity: ContractAddress,
            claim_topic: felt252,
            signature: Span<felt252>,
            data: ByteArray,
        ) -> bool {
            if self.is_claim_revoked(signature.clone()) {
                return false;
            }
            self.identity.is_claim_valid(identity, claim_topic, signature, data)
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        #[inline]
        fn _revoke_claim_by_signature(ref self: ContractState, signature: Span<felt252>) {
            let sig_hash = core::poseidon::poseidon_hash_span(signature);
            let revoked_claim_storage_path = self.revoked_claims.entry(sig_hash);
            assert(!revoked_claim_storage_path.read(), Errors::CLAIM_ALREADY_REVOKED);
            revoked_claim_storage_path.write(true);
            self.emit(ClaimRevoked { signature });
        }
    }
}
