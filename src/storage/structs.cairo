use core::num::traits::Zero;
use onchain_id_starknet::storage::storage::{MutableStorageArrayTrait, StorageArrayFelt252};
use starknet::ContractAddress;
use starknet::storage::{Mutable, StoragePath, StoragePointerWriteAccess};
// TODO: Go over comments
#[starknet::storage_node]
pub struct Key {
    /// Array of the key purposes, like 1 = MANAGEMENT, 2 = EXECUTION.
    pub purposes: StorageArrayFelt252,
    /// The type of key used, which would be a uint256 for different key types. e.g. 1 = ECDSA, 2 =
    /// RSA, etc.
    pub key_type: felt252,
    /// Hash of the public key or ContractAddress
    pub key: felt252,
}

#[starknet::storage_node]
pub struct Execution {
    /// The address of contract to call.
    pub to: ContractAddress,
    /// The entry point selector in the called contract.
    pub selector: felt252,
    /// The calldata to pass to entry point.
    pub calldata: StorageArrayFelt252,
    /// The bool that indicates if execution is approved or not.
    pub approved: bool,
    /// The bool that indicates if execution is already executed or not.
    pub executed: bool,
}
// TODO: Go over comments
#[starknet::storage_node]
pub struct Claim {
    /// A `felt252` which represents the topic of the claim. (e.g. 1 biometric, 2 residence etc...)
    pub topic: felt252,
    /// The scheme with which this claim SHOULD be verified or how it should be processed. Its a
    /// felt252 for different schemes. E.g. could 3 mean contract verification, where the data will
    /// be call data, and the issuer a contract address to call (ToBeDefined). Those can also mean
    /// different key types e.g. 1 = ECDSA, 2 = RSA, etc.
    /// (ToBeDefined)
    pub scheme: felt252,
    /// The issuers identity contract address, or the address used to sign the above signature. If
    /// an identity contract, it should hold the key with which the above message was signed, if the
    /// key is not present anymore, the claim SHOULD be treated as invalid. The issuer can also be a
    /// contract address itself, at which the claim can be verified using the call data.
    pub issuer: ContractAddress,
    /// Signature which is the proof that the claim issuer issued a claim of topic for this
    /// identity. it MUST be a signed message of the following structure: TODO: Define the SNIP12
    pub signature: StorageArrayFelt252,
    /// The hash of the claim data, sitting in another location, a bit-mask, call data, or actual
    /// data based on the claim scheme.
    pub data: ByteArray,
    /// The location of the claim, this can be HTTP links, swarm hashes, IPFS hashes, and such.
    pub uri: ByteArray,
}
// NOTE: Implement StoragePacking if this type of sig can comply with compact signatures

// Note: Assumes purposes are already cleared
pub fn delete_key(self: StoragePath<Mutable<Key>>) {
    self.key_type.write(Zero::zero());
    self.key.write(Zero::zero());
}

pub fn delete_claim(self: StoragePath<Mutable<Claim>>) {
    self.topic.write(Zero::zero());
    self.scheme.write(Zero::zero());
    self.issuer.write(Zero::zero());
    self.signature.deref().clear();
    self.data.write(Default::default());
    self.uri.write(Default::default());
}
