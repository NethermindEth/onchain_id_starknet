use starknet::ContractAddress;

#[starknet::interface]
pub trait ITrustedIssuersRegistry<TContractState> {
    fn add_trusted_issuer(
        ref self: TContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>,
    );
    fn remove_trusted_issuer(ref self: TContractState, trusted_issuer: ContractAddress);
    fn update_issuer_claim_topics(
        ref self: TContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>,
    );
    fn get_trusted_issuers(self: @TContractState) -> Array<ContractAddress>;
    fn get_trusted_issuers_for_claim_topic(
        self: @TContractState, claim_topic: felt252,
    ) -> Array<ContractAddress>;
    fn is_trusted_issuer(self: @TContractState, issuer: ContractAddress) -> bool;
    fn get_trusted_issuer_claim_topics(
        self: @TContractState, trusted_issuer: ContractAddress,
    ) -> Array<felt252>;
    fn has_claim_topic(
        self: @TContractState, issuer: ContractAddress, claim_topic: felt252,
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
    fn verify(self: @TContractState, identity: ContractAddress) -> bool;
    fn is_claim_topic_required(self: @TContractState, claim_topic: felt252) -> bool;
}

#[starknet::interface]
pub trait VerifierABI<TContractState> {
    // IVerifier
    fn verify(self: @TContractState, identity: ContractAddress) -> bool;
    fn is_claim_topic_required(self: @TContractState, claim_topic: felt252) -> bool;
    // ITrustedIssuersRegistry
    fn add_trusted_issuer(
        ref self: TContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>,
    );
    fn remove_trusted_issuer(ref self: TContractState, trusted_issuer: ContractAddress);
    fn update_issuer_claim_topics(
        ref self: TContractState, trusted_issuer: ContractAddress, claim_topics: Array<felt252>,
    );
    fn get_trusted_issuers(self: @TContractState) -> Array<ContractAddress>;
    fn get_trusted_issuers_for_claim_topic(
        self: @TContractState, claim_topic: felt252,
    ) -> Array<ContractAddress>;
    fn is_trusted_issuer(self: @TContractState, issuer: ContractAddress) -> bool;
    fn get_trusted_issuer_claim_topics(
        self: @TContractState, trusted_issuer: ContractAddress,
    ) -> Array<felt252>;
    fn has_claim_topic(
        self: @TContractState, issuer: ContractAddress, claim_topic: felt252,
    ) -> bool;
    // IClaimTopicsRegistry
    fn add_claim_topic(ref self: TContractState, claim_topic: felt252);
    fn remove_claim_topic(ref self: TContractState, claim_topic: felt252);
    fn get_claim_topics(self: @TContractState) -> Array<felt252>;
}
