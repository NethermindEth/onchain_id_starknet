use starknet::ContractAddress;

#[starknet::interface]
pub trait IIdentity<TContractState> {
    fn is_claim_valid(
        self: @TContractState,
        identity: ContractAddress,
        claim_topic: felt252,
        signature: Span<felt252>,
        data: ByteArray,
    ) -> bool;
}

#[starknet::interface]
pub trait IdentityABI<TContractState> {
    fn is_claim_valid(
        ref self: TContractState,
        identity: ContractAddress,
        claim_topic: felt252,
        signature: Span<felt252>,
        data: ByteArray,
    ) -> bool;
    // IERC734
    fn add_key(ref self: TContractState, key: felt252, purpose: felt252, key_type: felt252) -> bool;
    fn remove_key(ref self: TContractState, key: felt252, purpose: felt252) -> bool;
    fn approve(ref self: TContractState, execution_id: felt252, approve: bool) -> bool;
    fn execute(
        ref self: TContractState, to: ContractAddress, selector: felt252, calldata: Span<felt252>,
    ) -> felt252;
    fn get_key(ref self: TContractState, key: felt252) -> (Span<felt252>, felt252, felt252);
    fn get_key_purposes(ref self: TContractState, key: felt252) -> Span<felt252>;
    fn get_keys_by_purpose(ref self: TContractState, purpose: felt252) -> Span<felt252>;
    fn key_has_purpose(ref self: TContractState, key: felt252, purpose: felt252) -> bool;
    // IERC735
    fn add_claim(
        ref self: TContractState,
        topic: felt252,
        scheme: felt252,
        issuer: ContractAddress,
        signature: Span<felt252>,
        data: ByteArray,
        uri: ByteArray,
    ) -> felt252;
    fn remove_claim(ref self: TContractState, claim_id: felt252) -> bool;
    fn get_claim(
        ref self: TContractState, claim_id: felt252,
    ) -> (felt252, felt252, ContractAddress, Span<felt252>, ByteArray, ByteArray);
    fn get_claim_ids_by_topics(ref self: TContractState, topic: felt252) -> Span<felt252>;
}
