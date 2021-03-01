use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Sha3_512};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Keypair {
    secret_key: SecretKey,
    public_key: PublicKey,
    random_code: Random,
}
#[wasm_bindgen]
#[derive(Debug, Clone)]
#[repr(C)]
pub struct SharedKey {
    key: Box<[u8]>,
}
#[wasm_bindgen]
#[derive(Debug, Clone)]
#[repr(C)]
pub struct PublicKey {
    key: Box<[u8]>,
}
#[wasm_bindgen]
#[derive(Debug, Clone)]
#[repr(C)]
pub struct SecretKey {
    key: Box<[u8]>,
}
#[wasm_bindgen]
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Random {
    key: Box<[u8]>,
}
#[wasm_bindgen]
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Signature {
    key: Box<[u8]>, //64
}

#[wasm_bindgen]
pub fn wasm_key_gen_from_seed(seed: Option<Box<[u8]>>) -> Keypair {
    let mut hasher = Sha3_512::new();
    let seed = seed.unwrap();
    hasher.update(seed.as_ref());
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
        secret_key: SecretKey {
            key: sk.to_bytes().to_vec().into_boxed_slice(),
        },
        public_key: PublicKey {
            key: pk_compress.to_bytes().to_vec().into_boxed_slice(),
        },
        random_code: Random {
            key: random_code.to_vec().into_boxed_slice(),
        },
    }
}

#[wasm_bindgen]
pub fn wasm_derive_public_key(
    pk: Option<Box<[u8]>>,
    id: Option<Box<[u8]>>,
    r: Option<Box<[u8]>>,
) -> Keypair {
    let pk = pk.unwrap();
    let id = id.unwrap();
    let r = r.unwrap();

    let root_pk_point_compressed = CompressedRistretto::from_slice(pk.as_ref());
    let root_pk_point = root_pk_point_compressed.decompress().unwrap();
    // println!("pk is :{:?}", root_pk_point);

    let mut hasher = Sha3_512::new();
    hasher.update(pk.as_ref());
    hasher.update(id.as_ref());
    hasher.update(r.as_ref());
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
        secret_key: SecretKey {
            key: vec![0u8, 32].into_boxed_slice(),
        },
        public_key: PublicKey {
            key: pk_point_compossed.to_bytes().to_vec().into_boxed_slice(),
        },
        random_code: Random {
            key: random_code.to_vec().into_boxed_slice(),
        },
    }
}

#[wasm_bindgen]
pub fn wasm_dh(pk: Option<Box<[u8]>>, sk: Option<Box<[u8]>>) -> SharedKey {
    let pk = pk.unwrap();
    let sk = sk.unwrap();

    let mut sk_array: [u8; 32] = [0u8; 32];

    for i in 0..32 {
        sk_array[i] = sk[i];
    }

    let sk_scalar = Scalar::from_canonical_bytes(sk_array).unwrap();
    let pk_point_compressed = CompressedRistretto::from_slice(pk.as_ref());
    let pk_point = pk_point_compressed.decompress().unwrap();
    let secret = &sk_scalar * &pk_point;
    SharedKey {
        key: secret.compress().to_bytes().to_vec().into_boxed_slice(),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn wasm_sign(
    sk: Option<Box<[u8]>>,
    pk: Option<Box<[u8]>>,
    message: Option<Box<[u8]>>,
    nonce: Option<Box<[u8]>>,
) -> Signature {
    let sk = sk.unwrap();
    let pk = pk.unwrap();
    let message = message.unwrap();
    let nonce = nonce.unwrap();

    let mut sk_array: [u8; 32] = [0u8; 32];

    for i in 0..32 {
        sk_array[i] = sk[i];
    }

    let mut h = Sha3_512::new();
    let R: CompressedRistretto;
    let r: Scalar;
    let s: Scalar;
    let k: Scalar;

    let secret_key = Scalar::from_canonical_bytes(sk_array).unwrap();

    h.update(nonce.as_ref());
    h.update(message.as_ref());

    r = Scalar::from_hash(h);
    R = (&r * &RISTRETTO_BASEPOINT_TABLE).compress();

    h = Sha3_512::new();
    h.update(R.as_bytes());
    h.update(pk.as_ref());
    h.update(message.as_ref());

    k = Scalar::from_hash(h);
    s = &(&k * &secret_key) + &r;

    // InternalSignature { R, s }.into()
    // let is = InternalSignature { R, s };

    let mut sign_bytes = [0u8; 64];

    sign_bytes[..32].copy_from_slice(&R.as_bytes()[..]);
    sign_bytes[32..].copy_from_slice(&s.as_bytes()[..]);

    Signature {
        key: sign_bytes.to_vec().into_boxed_slice(),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn wasm_verify(
    s: Option<Box<[u8]>>,
    pk: Option<Box<[u8]>>,
    message: Option<Box<[u8]>>,
) -> bool {
    let s = s.unwrap();
    let pk = pk.unwrap();
    let message = message.unwrap();

    let mut lower: [u8; 32] = [0u8; 32];
    let mut upper: [u8; 32] = [0u8; 32];

    for i in 0..32 {
        lower[i] = s[i];
        upper[32 + i] = s[i + 32]
    }

    // lower.copy_from_slice(&s.key[..32]);
    // upper.copy_from_slice(&s.key[32..]);

    let ss = Scalar::from_bits(upper);
    let sR = CompressedRistretto::from_slice(&lower);

    let mut h = Sha3_512::new();
    // let R: CompressedRistretto;
    let k: Scalar;
    let pk_compossed = CompressedRistretto::from_slice(pk.as_ref());
    let pk_point = pk_compossed.decompress().unwrap();
    let minus_A = -pk_point;

    h.update(&lower);
    h.update(pk.as_ref());
    h.update(message.as_ref());

    k = Scalar::from_hash(h);
    let R = RistrettoPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &ss);

    R.compress() == sR

    // true
}

#[wasm_bindgen]
pub fn derive_secret_key(
    sk: Option<Box<[u8]>>,
    id: Option<Box<[u8]>>,
    r: Option<Box<[u8]>>,
) -> Keypair {
    let sk = sk.unwrap();
    let id = id.unwrap();
    let r = r.unwrap();

    let mut sk_array: [u8; 32] = [0; 32];

    for i in 0..32 {
        sk_array[i] = sk[i];
    }

    let sk_scalar = Scalar::from_canonical_bytes(sk_array.clone()).unwrap();

    let root_pk = &RISTRETTO_BASEPOINT_TABLE * &sk_scalar;

    let root_pk_compressed = root_pk.compress();

    // println!("pk is :{:?}", root_pk);

    let mut hasher = Sha3_512::new();
    hasher.update(root_pk_compressed.as_bytes());
    hasher.update(id.as_ref());
    hasher.update(r.as_ref());
    let result = hasher.finalize();
    let res_ref = &result[..];

    let mut secret_key = [0u8; 32];
    let mut random_code = [0u8; 32];

    secret_key.copy_from_slice(&res_ref[0..32]);
    random_code.copy_from_slice(&res_ref[32..]);

    let sk_point =
        Scalar::from_bytes_mod_order(secret_key) + Scalar::from_bytes_mod_order(sk_array);
    let pk_point = &RISTRETTO_BASEPOINT_TABLE * &sk_point;
    let pk_point_compossed = pk_point.compress();

    Keypair {
        secret_key: SecretKey {
            key: sk_point.to_bytes().to_vec().into_boxed_slice(),
        },
        public_key: PublicKey {
            key: pk_point_compossed.to_bytes().to_vec().into_boxed_slice(),
        },
        random_code: Random {
            key: random_code.to_vec().into_boxed_slice(),
        },
    }
}
