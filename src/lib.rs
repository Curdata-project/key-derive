use std::slice::from_raw_parts;

mod ristretto255;
mod wasm_ristretto255;

#[no_mangle]
pub extern "C" fn ristretto255_key_gen_from_seed(seed: *const u8) -> ristretto255::Keypair {
    let seed_slice = unsafe { from_raw_parts(seed, 32) };
    let mut seed_array = [0u8; 32];

    seed_array.copy_from_slice(seed_slice);

    ristretto255::key_gen_from_seed(seed_array)
}

#[no_mangle]
pub extern "C" fn ristretto255_dh(
    pk: ristretto255::PublicKey,
    sk: ristretto255::SecretKey,
) -> ristretto255::SharedKey {
    ristretto255::dh(pk, sk)
}

#[no_mangle]
pub extern "C" fn ristretto255_derive_secret_key(
    sk: ristretto255::SecretKey,
    id: ristretto255::Random,
    r: ristretto255::Random,
) -> ristretto255::Keypair {
    ristretto255::derive_secret_key(sk, id, r)
}

#[no_mangle]
pub extern "C" fn ristretto255_derive_public_key(
    pk: ristretto255::PublicKey,
    id: ristretto255::Random,
    r: ristretto255::Random,
) -> ristretto255::Keypair {
    ristretto255::derive_public_key(pk, id, r)
}

#[no_mangle]
pub extern "C" fn ristretto255_sign(
    sk: ristretto255::SecretKey,
    pk: ristretto255::PublicKey,
    message_ptr: *const u8,
    message_length: usize,
    nonce: ristretto255::Random,
) -> ristretto255::Signature {
    let message = unsafe { std::slice::from_raw_parts(message_ptr, message_length) };
    ristretto255::sign(sk, pk, message, nonce)
}

#[no_mangle]
pub extern "C" fn ristretto255_verify(
    s: ristretto255::Signature,
    pk: ristretto255::PublicKey,
    message_ptr: *const u8,
    message_length: usize,
) -> bool {
    let message = unsafe { std::slice::from_raw_parts(message_ptr, message_length) };
    ristretto255::verify(s, pk, message)
}
