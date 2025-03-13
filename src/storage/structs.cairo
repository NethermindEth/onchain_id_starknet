use core::num::traits::{Pow, Zero};
use starknet::ContractAddress;
use starknet::storage::Vec;
use starknet::storage_access::StorePacking;

/// Struct that holds details about key.
#[derive(Drop, Copy)]
pub struct KeyDetails {
    /// 128 bit bitmap. Capable of holding 128 purposes for a single key.
    pub purposes: u128,
    /// Indicates the type of the key.
    pub key_type: u64,
}

pub impl KeyDetailsPacking of StorePacking<KeyDetails, felt252> {
    fn pack(value: KeyDetails) -> felt252 {
        u256 { low: value.purposes, high: value.key_type.into() }.try_into().unwrap()
    }

    fn unpack(value: felt252) -> KeyDetails {
        let value_u256: u256 = value.into();
        KeyDetails { purposes: value_u256.low, key_type: value_u256.high.try_into().unwrap() }
    }
}

pub trait KeyDetailsTrait {
    fn grant_purpose(ref self: KeyDetails, purpose: felt252);
    fn revoke_purpose(ref self: KeyDetails, purpose: felt252);
    fn has_purpose(self: @KeyDetails, purpose: felt252) -> bool;
    fn get_all_purposes(self: @KeyDetails) -> Array<felt252>;
}

impl KeyDetailsImpl of KeyDetailsTrait {
    fn grant_purpose(ref self: KeyDetails, purpose: felt252) {
        BitmapTrait::set(ref self.purposes, purpose.try_into().expect('Invalid purpose'));
    }

    fn revoke_purpose(ref self: KeyDetails, purpose: felt252) {
        BitmapTrait::unset(ref self.purposes, purpose.try_into().expect('Invalid purpose'));
    }

    fn has_purpose(self: @KeyDetails, purpose: felt252) -> bool {
        BitmapTrait::get(*self.purposes, purpose.try_into().expect('Invalid purpose'))
    }

    fn get_all_purposes(self: @KeyDetails) -> Array<felt252> {
        let mut index = 0;
        let mut all_purposes = array![];
        let mut purposes = *self.purposes;
        while purposes.is_non_zero() {
            if (purposes % 2).is_non_zero() {
                all_purposes.append(index.into());
            }
            purposes /= 2;
            index += 1;
        }
        all_purposes
    }
}

trait BitmapTrait<T> {
    fn new() -> T;
    fn set(ref bitmap: T, index: usize);
    fn unset(ref bitmap: T, index: usize);
    fn get(bitmap: T, index: usize) -> bool;
}

impl BitmapTraitImpl of BitmapTrait<u128> {
    fn new() -> u128 {
        0
    }

    fn set(ref bitmap: u128, index: usize) {
        assert(index < 128, 'Index out of range');
        bitmap = bitmap | 2_u128.pow(index);
    }

    fn unset(ref bitmap: u128, index: usize) {
        assert(index < 128, 'Index out of range');
        bitmap = bitmap & (~2_u128.pow(index));
    }

    fn get(bitmap: u128, index: usize) -> bool {
        assert(index < 128, 'Index out of range');
        (bitmap & 2_u128.pow(index)).is_non_zero()
    }
}

#[derive(Drop, Copy, Serde, starknet::Store, PartialEq)]
pub enum ExecutionRequestStatus {
    #[default]
    PendingApproval,
    Approved,
    Rejected,
    Executed,
}

#[starknet::storage_node]
pub struct Execution {
    /// The address of contract to call.
    pub to: ContractAddress,
    /// The entry point selector in the called contract.
    pub selector: felt252,
    /// The calldata to pass to entry point.
    pub calldata: Vec<felt252>,
    /// Enum that stores information about status of execution request
    pub execution_request_status: ExecutionRequestStatus,
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
    pub signature: Vec<felt252>,
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
