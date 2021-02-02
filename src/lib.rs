use std::slice::from_raw_parts;

mod curve25519;

#[no_mangle]
pub extern "C" fn curve25519_key_gen_from_seed(seed: *const u8) -> curve25519::Keypair {
    let seed_slice = unsafe { from_raw_parts(seed, 32) };
    let mut seed_array = [0u8; 32];

    seed_array.copy_from_slice(seed_slice);

    curve25519::key_gen_from_seed(seed_array)
}

#[no_mangle]
pub extern "C" fn curve25519_dh(pk: curve25519::PublicKey, sk: curve25519::SecretKey) -> curve25519::SharedKey {
    curve25519::dh(pk, sk)
}

// #[no_mangle]
// pub extern "C" fn curve25519_derive_secret_key(sk: *const u8, id: *const u8, r: *const u8) -> Keypair {
//     let sk_slice = unsafe {
//         from_raw_parts(sk, 32)
//     };
//     let id_slice = unsafe {
//         from_raw_parts(id, 32)
//     };
//     let r_slice = unsafe {
//         from_raw_parts(r, 32)
//     };

//     let mut id = [0u8; 32];
//     let mut root_secret_key = [0u8; 32];
//     let mut random = [0u8; 32];

//     id.copy_from_slice(id_slice);
//     root_secret_key.copy_from_slice(sk_slice);
//     random.copy_from_slice(r_slice);

//     let root_pk = clamp_scalar(root_secret_key.clone()) * X25519_BASEPOINT;

//     // println!("pk is :{:?}", root_pk);

//     let mut hasher = Sha3_512::new();
//     hasher.update(root_pk.as_bytes());
//     hasher.update(r_slice);
//     hasher.update(id_slice);
//     let result = hasher.finalize();
//     let res_ref = &result[..];

//     let mut secret_key = [0u8; 32];
//     let mut random_code = [0u8; 32];

//     secret_key.copy_from_slice(&res_ref[0..32]);
//     random_code.copy_from_slice(&res_ref[32..]);

//     println!("{:?}", secret_key);
//     println!("{:?}", random_code);

//     let sk_point = clamp_scalar(secret_key) + clamp_scalar(root_secret_key);
//     let pk_point = sk_point * X25519_BASEPOINT;

//     Keypair {
//         screct_key: sk_point.to_bytes(),
//         public_key: pk_point.to_bytes(),
//         random_code
//     }
// }

// #[no_mangle]
// pub extern "C" fn curve25519_derive_public_key(pk: *const u8, id: *const u8, r: *const u8) -> Keypair {
//     let pk_slice = unsafe {
//         from_raw_parts(pk, 32)
//     };
//     let id_slice = unsafe {
//         from_raw_parts(id, 32)
//     };
//     let r_slice = unsafe {
//         from_raw_parts(r, 32)
//     };

//     let mut public_key = [0u8; 32];
//     public_key.copy_from_slice(pk_slice);
//     let root_pk_point = MontgomeryPoint(public_key);
//     // println!("pk is :{:?}", root_pk_point);

//     let mut hasher = Sha3_512::new();
//     hasher.update(root_pk_point.as_bytes());
//     hasher.update(r_slice);
//     hasher.update(id_slice);
//     let result = hasher.finalize();
//     let res_ref = &result[..];

//     let mut secret_key = [0u8; 32];
//     let mut random_code = [0u8; 32];

//     secret_key.copy_from_slice(&res_ref[0..32]);
//     random_code.copy_from_slice(&res_ref[32..]);

//     println!("{:?}", secret_key);
//     println!("{:?}", random_code);

//     let part_pk_point = clamp_scalar(secret_key) * X25519_BASEPOINT;

//     let pk_point = &part_pk_point + &root_pk_point;

//     Keypair {
//         screct_key: [0u8; 32],
//         public_key: pk_point.to_bytes(),
//         random_code
//     }
// }
