use super::*;
use ed25519_dalek::{Digest as _, Sha512};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Serialize, Deserialize)]
struct Message {
    content: String,
}

impl Message {
    fn digest(&self) -> Digest {
        Digest(
            Sha512::digest(self.content.as_ref()).as_slice()[..32]
                .try_into()
                .unwrap(),
        )
    }
}

pub fn keys() -> Vec<(PublicKey, KeyPair)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| KeyPair::generate_keypair(&mut rng))
        .collect()
}

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let (public_key, keypair) = keys().pop().unwrap();

    // Make signature.
    let message = Message {
        content: "Hello, world!".to_string(),
    };
    let signature = Signature::new(&message.digest(), &keypair);

    // Verify the signature.
    assert!(signature.verify(&message.digest(), &public_key).is_ok());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let (public_key, keypair) = keys().pop().unwrap();

    // Make signature.
    let message = Message {
        content: "Hello, world!".to_string(),
    };
    let signature = Signature::new(&message.digest(), &keypair);

    // Verify the signature.
    let bad_message = Message {
        content: "Bad message!".to_string(),
    };
    assert!(signature
        .verify(&bad_message.digest(), &public_key)
        .is_err());
}

#[test]
fn verify_valid_batch() {
    // Make signatures.
    let message = Message {
        content: "Hello, world!".to_string(),
    };
    let mut keys = keys();
    let signatures: Vec<_> = (0..3)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&message.digest(), &secret_key))
        })
        .collect();

    // Verify the batch.
    assert!(Signature::verify_batch(&message.digest(), &signatures).is_ok());
}

#[test]
fn verify_invalid_batch() {
    // Make 2 valid signatures.
    let message = Message {
        content: "Hello, world!".to_string(),
    };
    let mut keys = keys();
    let mut signatures: Vec<_> = (0..2)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&message.digest(), &secret_key))
        })
        .collect();

    // Add an invalid signature.
    let (public_key, _) = keys.pop().unwrap();
    signatures.push((public_key, Signature::default()));

    // Verify the batch.
    assert!(Signature::verify_batch(&message.digest(), &signatures).is_err());
}
