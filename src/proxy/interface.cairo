use starknet::ClassHash;

#[starknet::interface]
pub trait IIdentityImplementationAuthority<TContractState> {
    fn update_implementation(ref self: TContractState, new_class_hash: ClassHash);
    fn upgrade_identity(ref self: TContractState);
    fn get_implementation(self: @TContractState) -> ClassHash;
}
