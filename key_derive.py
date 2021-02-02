from ctypes import *

_derive_key = cdll.LoadLibrary("target/debug/libderive_key.so")

class Keypair(Structure):
    _fields_ = [
        ("screct_key", c_char * 32),
        ("public_key", c_char * 32),
        ("random_code", c_char * 32),
    ]

class SharedKey(Structure):
    _fields_ = [
        ("key", c_char * 32),
    ]

_derive_key.curve25519_key_gen_from_seed.argtypes = [POINTER(c_char)]
_derive_key.curve25519_key_gen_from_seed.restype = Keypair

def curve25519_key_gen_from_seed(b):
    return _derive_key.curve25519_key_gen_from_seed(b)

_derive_key.curve25519_dh.argtypes = [POINTER(c_char), POINTER(c_char)]
_derive_key.curve25519_dh.restype = SharedKey

def curve25519_dh(pk, sk):
    p = _derive_key.curve25519_dh(pk, sk)
    return p

# _derive_key.curve25519_derive_secret_key.argtypes = [POINTER(c_char), POINTER(c_char), POINTER(c_char)]
# _derive_key.curve25519_derive_secret_key.restype = Keypair

# def curve25519_derive_secret_key(sk, i, r):
#     return _derive_key.curve25519_derive_secret_key(sk, i, r)

# _derive_key.curve25519_derive_public_key.argtypes = [POINTER(c_char), POINTER(c_char), POINTER(c_char)]
# _derive_key.curve25519_derive_public_key.restype = Keypair

# def curve25519_derive_public_key(pk, i, r):
#     return _derive_key.curve25519_derive_public_key(pk, i, r)

def _main():
    import secrets
    seed1 = secrets.token_bytes(32)
    kp1 = curve25519_key_gen_from_seed(seed1)
    # print('kp1.public_key', kp1.public_key)
    # print('kp1.screct_key', kp1.screct_key)

    seed2 = secrets.token_bytes(32)
    kp2 = curve25519_key_gen_from_seed(seed2)
    res1 = curve25519_dh(kp1.public_key, kp2.screct_key)
    res2 = curve25519_dh(kp2.public_key, kp1.screct_key)
    # print('shared secret:', res1.key)
    # print('shared secret:', res2.key)
    print(res1.key == res2.key)

    # res = curve25519_derive_secret_key(kp1.screct_key, seed2, kp1.random_code)
    # res1 = curve25519_derive_public_key(kp1.public_key, seed2, kp1.random_code)
    # print(res.public_key)
    # # print(res.screct_key)
    # print(res1.public_key)

if __name__ == '__main__':
    for _ in range(30):
        _main()
    
