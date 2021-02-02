use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Sha3_512};

#[repr(C)]
pub struct Keypair {
    screct_key: [u8; 32],
    public_key: [u8; 32],
    random_code: [u8; 32],
}

#[repr(C)]
pub struct SharedKey {
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
        screct_key: sk.to_bytes(),
        public_key: pk_point.to_bytes(),
        random_code,
    }
}

pub fn dh(pk: [u8; 32], sk: [u8; 32]) -> SharedKey {
    SharedKey {
        key: (clamp_scalar(sk) * MontgomeryPoint(pk)).to_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rand::RngCore;
    #[test]
    fn test_dh() {
        for i in 0..10 {
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
}
