use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Sha3_512};

#[repr(C)]
pub struct Keypair {
    screct_key: SecretKey,
    public_key: PublicKey,
    random_code: Random,
}

#[repr(C)]
pub struct SharedKey {
    key: [u8; 32],
}

#[repr(C)]
pub struct PublicKey {
    key: [u8; 32],
}

#[repr(C)]
pub struct SecretKey {
    key: [u8; 32],
}

#[repr(C)]
pub struct Random {
    key: [u8; 32],
}

fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}

pub fn key_gen_from_seed(seed: [u8; 32]) -> Keypair {
    let mut hasher = Sha3_512::new();
    hasher.update(&seed);
    let result = hasher.finalize();
    let res_ref = &result[..];
    let mut screct_key = [0u8; 32];
    let mut random_code = [0u8; 32];

    screct_key.copy_from_slice(&res_ref[0..32]);
    random_code.copy_from_slice(&res_ref[32..64]);

    let sk = clamp_scalar(screct_key);

    let pk_point = (&ED25519_BASEPOINT_TABLE * &clamp_scalar(screct_key)).to_montgomery();

    Keypair {
        screct_key: SecretKey { key: sk.to_bytes() },
        public_key: PublicKey {
            key: pk_point.to_bytes(),
        },
        random_code: Random { key: random_code },
    }
}

pub fn dh(pk: PublicKey, sk: SecretKey) -> SharedKey {
    SharedKey {
        key: (clamp_scalar(sk.key) * MontgomeryPoint(pk.key)).to_bytes(),
    }
}

pub fn derive_secret_key(sk: SecretKey, id: Random, r: Random) -> Keypair {
    let root_pk = (&ED25519_BASEPOINT_TABLE * &clamp_scalar(sk.key)).to_montgomery();

    // println!("pk is :{:?}", root_pk);

    let mut hasher = Sha3_512::new();
    hasher.update(root_pk.as_bytes());
    hasher.update(&id.key);
    hasher.update(&r.key);
    let result = hasher.finalize();
    let res_ref = &result[..];

    let mut secret_key = [0u8; 32];
    let mut random_code = [0u8; 32];

    secret_key.copy_from_slice(&res_ref[0..32]);
    random_code.copy_from_slice(&res_ref[32..]);

    println!("{:?}", secret_key);
    println!("{:?}", random_code);

    let sk_point = clamp_scalar(secret_key) + clamp_scalar(sk.key);
    let pk_point = (&ED25519_BASEPOINT_TABLE * &sk_point).to_montgomery();

    Keypair {
        screct_key: SecretKey { key: sk_point.to_bytes() },
        public_key: PublicKey {
            key: pk_point.to_bytes(),
        },
        random_code: Random { key: random_code },
    }
}

// pub fn derive_public_key(sk: SecretKey, id: Random, r: Random) -> Keypair {

// }

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rand::RngCore;
    #[test]
    fn test_dh() {
        for _ in 0..10 {
            let mut rng = thread_rng();
            let mut seed1 = [0u8; 32];
            rng.fill_bytes(&mut seed1);
            let mut seed2 = [0u8; 32];
            rng.fill_bytes(&mut seed2);

            let kp1 = key_gen_from_seed(seed1);
            let kp2 = key_gen_from_seed(seed2);

            let sk1 = dh(kp1.public_key, kp2.screct_key);
            let sk2 = dh(kp2.public_key, kp1.screct_key);

            assert_eq!(sk1.key, sk2.key);
        }
    }

    #[test]
    fn test_derive() {}
}
