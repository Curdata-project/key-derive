use sha3::{Digest, Sha3_512};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::X25519_BASEPOINT;
use std::slice::from_raw_parts;

#[repr(C)]
pub struct Keypair {
    screct_key: [u8; 32],
    public_key: [u8; 32],
    random_code: [u8; 32],
}

fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}

#[no_mangle]
pub extern "C" fn curve25519_key_gen_from_seed(seed: *const u8) -> Keypair {
    let seed_slice = unsafe {
        from_raw_parts(seed, 32)
    };
    let mut hasher = Sha3_512::new();
    hasher.update(seed_slice);
    let result = hasher.finalize();
    let res_ref = &result[..];
    let mut screct_key = [0u8; 32];
    let mut random_code = [0u8; 32];

    screct_key.copy_from_slice(&res_ref[0..32]);
    random_code.copy_from_slice(&res_ref[32..64]);

    let pk_point = clamp_scalar(screct_key) * X25519_BASEPOINT;

    Keypair {
        screct_key,
        public_key: pk_point.to_bytes(),
        random_code
    }
}

#[no_mangle]
pub extern "C" fn curve25519_dh(pk: *const u8, sk: *const u8) -> *const u8 {
    let pk_slice = unsafe {
        from_raw_parts(pk, 32)
    };
    let sk_slice = unsafe {
        from_raw_parts(sk, 32)
    };
    let mut public_key = [0u8; 32];
    let mut secret_key = [0u8; 32];
    public_key.copy_from_slice(pk_slice);
    secret_key.copy_from_slice(sk_slice);
    let bytes = (clamp_scalar(secret_key) * MontgomeryPoint(public_key)).to_bytes();
    bytes.as_ptr()
}

#[no_mangle]
pub extern "C" fn curve25519_derive_secret_key(sk: *const u8, id: *const u8, r: *const u8) -> Keypair {
    let sk_slice = unsafe {
        from_raw_parts(sk, 32)
    };
    let id_slice = unsafe {
        from_raw_parts(id, 32)
    };
    let r_slice = unsafe {
        from_raw_parts(r, 32)
    };

    let mut id = [0u8; 32];
    let mut root_secret_key = [0u8; 32];
    let mut random = [0u8; 32];

    id.copy_from_slice(id_slice);
    root_secret_key.copy_from_slice(sk_slice);
    random.copy_from_slice(r_slice);

    let root_pk = clamp_scalar(root_secret_key) * X25519_BASEPOINT;

    let mut hasher = Sha3_512::new();
    hasher.update(root_pk.as_bytes());
    hasher.update(r_slice);
    hasher.update(id_slice);
    let result = hasher.finalize();
    let res_ref = &result[..];

    let mut secret_key = [0u8; 32];
    let mut random_code = [0u8; 32];

    secret_key.copy_from_slice(&res_ref[0..32]);
    random_code.copy_from_slice(&res_ref[32..]);

    println!("{:?}", secret_key);
    println!("{:?}", random_code);

    let sk_point = clamp_scalar(secret_key) + clamp_scalar(root_secret_key);
    let pk_point = sk_point * X25519_BASEPOINT;

    Keypair {
        screct_key: sk_point.to_bytes(),
        public_key: pk_point.to_bytes(),
        random_code
    }
}

#[no_mangle]
pub extern "C" fn curve25519_derive_public_key(pk: *const u8, id: *const u8, r: *const u8) -> *const u8 {
    let pk_slice = unsafe {
        from_raw_parts(pk, 32)
    };
    let id_slice = unsafe {
        from_raw_parts(id, 32)
    };
    let r_slice = unsafe {
        from_raw_parts(r, 32)
    };

    
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(pk_slice);

    let mut hasher = Sha3_512::new();
    hasher.update(pk_slice);
    hasher.update(r_slice);
    hasher.update(id_slice);
    let result = hasher.finalize();
    let res_ref = &result[..];

    let mut secret_key = [0u8; 32];
    let mut random_code = [0u8; 32];

    secret_key.copy_from_slice(&res_ref[0..32]);
    random_code.copy_from_slice(&res_ref[32..]);
    
    println!("{:?}", secret_key);
    println!("{:?}", random_code);

    let part_pk_point = clamp_scalar(secret_key) * X25519_BASEPOINT;
    let root_pk_point = MontgomeryPoint(public_key);
    let ed_part_pk_point = part_pk_point.to_edwards(0).unwrap();
    let ed_root_pk_point = root_pk_point.to_edwards(0).unwrap();
    let pk_point = ed_part_pk_point + ed_root_pk_point;
    pk_point.to_montgomery().to_bytes().as_ptr()
}
