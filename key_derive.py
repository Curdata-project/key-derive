from ctypes import *

_derive_key = cdll.LoadLibrary("target/release/libderive_key.so")

class SharedKey(Structure):
    _fields_ = [
        ("key", c_char * 32),
    ]

class PublicKey(Structure):
    _fields_ = [
        ("key", c_char * 32),
    ]

class SecretKey(Structure):
    _fields_ = [
        ("key", c_char * 32),
    ]

class Random(Structure):
    _fields_ = [
        ("key", c_char * 32),
    ]

class Keypair(Structure):
    _fields_ = [
        ("secret_key", SecretKey),
        ("public_key", PublicKey),
        ("random_code", Random),
    ]

_derive_key.ristretto255_key_gen_from_seed.argtypes = [POINTER(c_char)]
_derive_key.ristretto255_key_gen_from_seed.restype = Keypair

def ristretto255_key_gen_from_seed(b):
    return _derive_key.ristretto255_key_gen_from_seed(b)

_derive_key.ristretto255_dh.argtypes = [PublicKey, SecretKey]
_derive_key.ristretto255_dh.restype = SharedKey

def ristretto255_dh(pk, sk):
    p = _derive_key.ristretto255_dh(pk, sk)
    return p

_derive_key.ristretto255_derive_secret_key.argtypes = [SecretKey, Random, Random]
_derive_key.ristretto255_derive_secret_key.restype = Keypair

def ristretto255_derive_secret_key(sk, i, r):
    return _derive_key.ristretto255_derive_secret_key(sk, i, r)

_derive_key.ristretto255_derive_public_key.argtypes = [PublicKey, Random, Random]
_derive_key.ristretto255_derive_public_key.restype = Keypair

def ristretto255_derive_public_key(pk, i, r):
    return _derive_key.ristretto255_derive_public_key(pk, i, r)

def _main():
    import secrets
    seed1 = secrets.token_bytes(32)
    kp1 = ristretto255_key_gen_from_seed(seed1)

    seed2 = secrets.token_bytes(32)
    kp2 = ristretto255_key_gen_from_seed(seed2)
    res1 = ristretto255_dh(kp1.public_key, kp2.secret_key)
    res2 = ristretto255_dh(kp2.public_key, kp1.secret_key)
    print(res1.key == res2.key)

    res = ristretto255_derive_secret_key(kp1.secret_key, kp1.random_code, kp1.random_code)
    res1 = ristretto255_derive_public_key(kp1.public_key, kp1.random_code, kp1.random_code)
    print(res.public_key.key == res1.public_key.key)

if __name__ == '__main__':
    for _ in range(30):
        _main()
    
