use starknet::ContractAddress;

#[event]
#[derive(Drop, starknet::Event)]
pub enum ERC735Event {
    ClaimAdded: ClaimAdded,
    ClaimRemoved: ClaimRemoved,
    ClaimChanged: ClaimChanged,
}

#[derive(Drop, starknet::Event)]
pub struct ClaimAdded {
    #[key]
    pub claim_id: felt252,
    #[key]
    pub topic: felt252,
    pub scheme: felt252,
    #[key]
    pub issuer: ContractAddress,
    pub signature: Span<felt252>,
    pub uri: ByteArray,
    pub data: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct ClaimRemoved {
    #[key]
    pub claim_id: felt252,
    #[key]
    pub topic: felt252,
    pub scheme: felt252,
    #[key]
    pub issuer: ContractAddress,
    pub signature: Span<felt252>,
    pub uri: ByteArray,
    pub data: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct ClaimChanged {
    #[key]
    pub claim_id: felt252,
    #[key]
    pub topic: felt252,
    pub scheme: felt252,
    #[key]
    pub issuer: ContractAddress,
    pub signature: Span<felt252>,
    pub uri: ByteArray,
    pub data: ByteArray,
}

#[starknet::interface]
pub trait IERC735<TContractState> {
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
        self: @TContractState, claim_id: felt252,
    ) -> (
        felt252, felt252, ContractAddress, Span<felt252>, ByteArray, ByteArray,
    ); // NOTE: turn this into a struct?
    fn get_claim_ids_by_topics(self: @TContractState, topic: felt252) -> Span<felt252>;
}
