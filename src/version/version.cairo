#[starknet::interface]
pub trait IVersion<TContractState> {
    fn version(self: @TContractState) -> felt252;
}

pub const VERSION: felt252 = '0.1.0';

#[starknet::embeddable]
pub impl VersionImpl<TContractState> of IVersion<TContractState> {
    fn version(self: @TContractState) -> felt252 {
        VERSION
    }
}
