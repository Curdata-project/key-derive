use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::*;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Sha3_512};

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Keypair {
    secret_key: SecretKey,
    public_key: PublicKey,
    random_code: Random,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct SharedKey {
    key: [u8; 32],
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct PublicKey {
    key: [u8; 32],
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct SecretKey {
    key: [u8; 32],
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Random {
    key: [u8; 32],
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Signature {
    key: [u8; 64],
}

pub fn key_gen_from_seed(seed: [u8; 32]) -> Keypair {
    let mut hasher = Sha3_512::new();
    hasher.update(&seed);
    let result = hasher.finalize();
    let res_ref = &result[..];
    let mut secret_key = [0u8; 32];
    let mut random_code = [0u8; 32];

    secret_key.copy_from_slice(&res_ref[0..32]);
    random_code.copy_from_slice(&res_ref[32..64]);

    let sk = Scalar::from_bytes_mod_order(secret_key);

    let pk_point = &RISTRETTO_BASEPOINT_TABLE * &sk;

    let pk_compress = pk_point.compress();

    Keypair {
        secret_key: SecretKey { key: sk.to_bytes() },
        public_key: PublicKey {
            key: pk_compress.to_bytes(),
        },
        random_code: Random { key: random_code },
    }
}

pub fn dh(pk: PublicKey, sk: SecretKey) -> SharedKey {
    let sk_scalar = Scalar::from_canonical_bytes(sk.key).unwrap();
    let pk_point_compressed = CompressedRistretto::from_slice(&pk.key);
    let pk_point = pk_point_compressed.decompress().unwrap();
    let secret = &sk_scalar * &pk_point;
    SharedKey {
        key: secret.compress().to_bytes(),
    }
}

#[allow(non_snake_case)]
pub fn sign(sk: SecretKey, pk: PublicKey, message: &[u8], nonce: Random) -> Signature {
    let mut h = Sha3_512::new();
    let R: CompressedRistretto;
    let r: Scalar;
    let s: Scalar;
    let k: Scalar;

    let secret_key = Scalar::from_canonical_bytes(sk.key).unwrap();

    h.update(nonce.key);
    h.update(&message);

    r = Scalar::from_hash(h);
    R = (&r * &RISTRETTO_BASEPOINT_TABLE).compress();

    h = Sha3_512::new();
    h.update(R.as_bytes());
    h.update(pk.key);
    h.update(&message);

    k = Scalar::from_hash(h);
    s = &(&k * &secret_key) + &r;

    // InternalSignature { R, s }.into()
    // let is = InternalSignature { R, s };

    let mut sign_bytes = [0u8; 64];

    sign_bytes[..32].copy_from_slice(&R.as_bytes()[..]);
    sign_bytes[32..].copy_from_slice(&s.as_bytes()[..]);

    Signature { key: sign_bytes }
}

#[allow(non_snake_case)]
pub fn verify(s: Signature, pk: PublicKey, message: &[u8]) -> bool {
    let mut lower: [u8; 32] = [0u8; 32];
    let mut upper: [u8; 32] = [0u8; 32];

    lower.copy_from_slice(&s.key[..32]);
    upper.copy_from_slice(&s.key[32..]);

    let ss = Scalar::from_bits(upper);
    let sR = CompressedRistretto::from_slice(&lower);

    let mut h = Sha3_512::new();
    // let R: CompressedRistretto;
    let k: Scalar;
    let pk_compossed = CompressedRistretto::from_slice(&pk.key);
    let pk_point = pk_compossed.decompress().unwrap();
    let minus_A = -pk_point;

    h.update(&s.key[..32]);
    h.update(&pk.key);
    h.update(&message);

    k = Scalar::from_hash(h);
    let R = RistrettoPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &ss);

    R.compress() == sR

    // true
}

pub fn derive_secret_key(sk: SecretKey, id: Random, r: Random) -> Keypair {
    let sk_scalar = Scalar::from_canonical_bytes(sk.key).unwrap();

    let root_pk = &RISTRETTO_BASEPOINT_TABLE * &sk_scalar;

    let root_pk_compressed = root_pk.compress();

    // println!("pk is :{:?}", root_pk);

    let mut hasher = Sha3_512::new();
    hasher.update(root_pk_compressed.as_bytes());
    hasher.update(&id.key);
    hasher.update(&r.key);
    let result = hasher.finalize();
    let res_ref = &result[..];

    let mut secret_key = [0u8; 32];
    let mut random_code = [0u8; 32];

    secret_key.copy_from_slice(&res_ref[0..32]);
    random_code.copy_from_slice(&res_ref[32..]);

    let sk_point = Scalar::from_bytes_mod_order(secret_key) + Scalar::from_bytes_mod_order(sk.key);
    let pk_point = &RISTRETTO_BASEPOINT_TABLE * &sk_point;
    let pk_point_compossed = pk_point.compress();

    Keypair {
        secret_key: SecretKey {
            key: sk_point.to_bytes(),
        },
        public_key: PublicKey {
            key: pk_point_compossed.to_bytes(),
        },
        random_code: Random { key: random_code },
    }
}

pub fn derive_public_key(pk: PublicKey, id: Random, r: Random) -> Keypair {
    let root_pk_point_compressed = CompressedRistretto::from_slice(&pk.key);
    let root_pk_point = root_pk_point_compressed.decompress().unwrap();
    // println!("pk is :{:?}", root_pk_point);

    let mut hasher = Sha3_512::new();
    hasher.update(&pk.key);
    hasher.update(&id.key);
    hasher.update(&r.key);
    let result = hasher.finalize();
    let res_ref = &result[..];

    let mut secret_key = [0u8; 32];
    let mut random_code = [0u8; 32];

    secret_key.copy_from_slice(&res_ref[0..32]);
    random_code.copy_from_slice(&res_ref[32..]);

    let part_pk_point = &RISTRETTO_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(secret_key);

    let pk_point = &part_pk_point + &root_pk_point;
    let pk_point_compossed = pk_point.compress();

    Keypair {
        secret_key: SecretKey { key: [0u8; 32] },
        public_key: PublicKey {
            key: pk_point_compossed.to_bytes(),
        },
        random_code: Random { key: random_code },
    }
}

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

            let sk1 = dh(kp1.public_key, kp2.secret_key);
            let sk2 = dh(kp2.public_key, kp1.secret_key);

            println!("{:?}", sk2);

            assert_eq!(sk1.key, sk2.key);
        }
    }

    #[test]
    fn test_derive() {
        for _ in 0..10 {
            let mut rng = thread_rng();
            let mut seed1 = [0u8; 32];
            rng.fill_bytes(&mut seed1);
            let mut id = [0u8; 32];
            rng.fill_bytes(&mut id);

            let kp1 = key_gen_from_seed(seed1);

            let new_key1 = derive_secret_key(
                kp1.secret_key,
                kp1.random_code.clone(),
                kp1.random_code.clone(),
            );
            // println!("{:?}", new_key1);

            let new_key2 =
                derive_public_key(kp1.public_key, kp1.random_code.clone(), kp1.random_code);
            // println!("{:?}", new_key2);

            println!("{}", new_key1.public_key.key == new_key2.public_key.key);
        }
    }
}
