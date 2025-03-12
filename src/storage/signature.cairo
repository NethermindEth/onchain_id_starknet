use core::poseidon::poseidon_hash_span;

#[derive(Copy, Drop, Serde)]
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
