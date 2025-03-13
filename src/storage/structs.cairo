use core::num::traits::{Zero, Pow};
use onchain_id_starknet::storage::storage::StorageArrayFelt252;
use starknet::storage_access::StorePacking;
use starknet::ContractAddress;

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

pub trait BitmapTrait<T> {
    fn set(bitmap: T, index: usize) -> T;
    fn unset(bitmap: T, index: usize) -> T;
    fn get(bitmap: T, index: usize) -> bool;
}

impl BitmapTraitImpl of BitmapTrait<u128> {
    fn set(bitmap: u128, index: usize) -> u128 {
        bitmap | 2_u128.pow(index)
    }

    fn unset(bitmap: u128, index: usize) -> u128 {
        bitmap & (~2_u128.pow(index))
    }

    fn get(bitmap: u128, index: usize) -> bool {
        (bitmap & 2_u128.pow(index)).is_non_zero()
    }
}

/// Returns all the purposes stored in bitmap.
pub fn get_all_purposes(purposes: u128) -> Array<felt252> {
    let mut index = 0;
    let mut all_purposes = array![];
    let mut purpouse_invariant = purposes;
    while purpouse_invariant.is_non_zero() {
        if (purpouse_invariant & 1).is_non_zero() {
            all_purposes.append(index.into());
        }
        purpouse_invariant /= 2;
        index += 1;
    }
    all_purposes
}

#[starknet::storage_node]
pub struct Execution {
    /// The address of contract to call.
    pub to: ContractAddress,
    /// The entry point selector in the called contract.
    pub selector: felt252,
    /// The calldata to pass to entry point.
    pub calldata: StorageArrayFelt252,
    /// Bitmap that holds execution request status. index 0 is approved, index 1 is rejected, index
    /// 2 is executed.
    pub execution_request_status: u128,
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
