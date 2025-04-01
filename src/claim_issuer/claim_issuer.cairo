//! The `ClaimIssuer` contract extends the core functionalities of the OnchainID protocol by
//! introducing a robust claim revocation mechanism. It allows for the management of claims
//! associated with identities, ensuring that claims can be revoked when necessary, thus
//! maintaining the integrity of identity management.
//!
//! # Features
//!
//! - **Claim Revocation**: Provides a mechanism to revoke claims by their signatures, ensuring
//!   that revoked claims are no longer considered valid.
//!
//! # Components
//!
//! - **IdentityComponent**: Utilized for core identity functionalities, including key management,
//! claim
//!   management, and validation.
//!
//! # Security Notice
//!
//! This contract has not undergone a formal security audit and should be considered experimental.
//! Users should exercise caution when implementing or deploying this code in production
//! environments.

#[starknet::contract]
pub mod ClaimIssuer {
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use crate::claim_issuer::interface::IClaimIssuer;
    use crate::identity::component::IdentityComponent;
    use crate::identity::interface::ierc735::{IERC735Dispatcher, IERC735DispatcherTrait};
    use crate::identity::interface::iidentity::IIdentity;
    use crate::version::version;

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
        /// Revokes a claim by its signature; the claim is no longer valid after revocation.
        fn revoke_claim_by_signature(ref self: ContractState, signature: Span<felt252>) {
            self.identity.only_manager();
            self._revoke_claim_by_signature(signature);
        }

        /// Revokes a claim by its claim_id; the claim is no longer valid after revocation.
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

        /// Determines if a claim is revoked by its signature and returns a `bool` indicating
        /// whether the claim is revoked or not.
        fn is_claim_revoked(self: @ContractState, signature: Span<felt252>) -> bool {
            let sig_hash = core::poseidon::poseidon_hash_span(signature);
            self.revoked_claims.entry(sig_hash).read()
        }
    }

    #[abi(embed_v0)]
    impl IdentityImpl of IIdentity<ContractState> {
        /// Checks if a claim is valid for the given identity.
        ///
        /// # Arguments
        ///
        /// * `identity` - `ContractAddress` representing the identity related to the claim.
        /// * `claim_topic` - `felt252` representing the topic of the claim.
        /// * `signature` - `Span<felt252>` representing the signature of the claim.
        /// * `data` - `ByteArray` representing the data field of the claim.
        ///
        /// # Requirements
        ///
        /// - The issuer of the claim should have a key with CLAIM purpose on the identity.
        ///
        /// # Returns
        ///
        /// A `bool` indicating whether the claim is valid or not.
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
