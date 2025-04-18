use core::hash::{HashStateExTrait, HashStateTrait};
use core::poseidon::{PoseidonTrait, poseidon_hash_span};
use openzeppelin_utils::cryptography::snip12::{SNIP12HashSpanImpl, StructHash};
use starknet::ContractAddress;

#[derive(Copy, Drop, Serde, PartialEq)]
pub struct StarkSignature {
    pub r: felt252,
    pub s: felt252,
    pub public_key: felt252,
}

#[derive(Copy, Drop)]
pub enum Signature {
    StarkSignature: StarkSignature,
}

impl SignatureSerde of Serde<Signature> {
    fn serialize(self: @Signature, ref output: Array<felt252>) {
        match self {
            Signature::StarkSignature(sig) => {
                output.append('StarkSignature');
                sig.serialize(ref output)
            },
            _ => panic!("Invalid kind"),
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<Signature> {
        let kind = *serialized.pop_front().unwrap();
        if kind == 'StarkSignature' {
            return Option::Some(
                Signature::StarkSignature(
                    Serde::<StarkSignature>::deserialize(ref serialized).expect('Invalid format'),
                ),
            );
        }
        Option::None
    }
}

pub fn is_valid_signature(message_hash: felt252, signature: Span<felt252>) -> bool {
    let mut signature_span = signature;
    let signature = Serde::<Signature>::deserialize(ref signature_span)
        .expect('Invalid formatting');
    match signature {
        Signature::StarkSignature(sig) => {
            core::ecdsa::check_ecdsa_signature(message_hash, sig.public_key, sig.r, sig.s)
        },
        _ => panic!("Invalid type"),
    }
}

pub fn get_public_key_hash(signature: Span<felt252>) -> felt252 {
    let mut signature_span = signature;
    let signature = Serde::<Signature>::deserialize(ref signature_span)
        .expect('Invalid formatting');
    match signature {
        Signature::StarkSignature(sig) => poseidon_hash_span(array![sig.public_key.into()].span()),
        _ => panic!("Invalid type"),
    }
}

pub const CLAIM_MESSAGE_TYPE_HASH: felt252 = selector!(
    "\"ClaimMessage\"(
        \"identity\":\"ContractAddress\",
        \"topic\":\"felt\",
        \"data\":\"felt*\",
    )",
);

#[derive(Drop, Copy, Serde)]
pub struct ClaimMessage {
    pub identity: ContractAddress,
    pub topic: felt252,
    pub data: Span<felt252>,
}

pub impl ClaimMessageStructHash of StructHash<ClaimMessage> {
    fn hash_struct(self: @ClaimMessage) -> felt252 {
        PoseidonTrait::new()
            .update_with(CLAIM_MESSAGE_TYPE_HASH)
            .update_with(*self.identity)
            .update_with(*self.topic)
            .update_with(*self.data)
            .finalize()
    }
}
