from ctypes import *

_derive_key = cdll.LoadLibrary("target/release/libderive_key.so")

class Py32LengthKey:
    def __init__(self, key):
        self.key = bytes(key)

class SharedKey(Structure):
    _fields_ = [
        ("key", c_byte * 32),
    ]

class PublicKey(Structure):
    _fields_ = [
        ("key", c_byte * 32),
    ]

class SecretKey(Structure):
    _fields_ = [
        ("key", c_byte * 32),
    ]

class Random(Structure):
    _fields_ = [
        ("key", c_byte * 32),
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
    keypair = _derive_key.ristretto255_key_gen_from_seed(b)
    return keypair

_derive_key.ristretto255_dh.argtypes = [PublicKey, SecretKey]
_derive_key.ristretto255_dh.restype = SharedKey

def ristretto255_dh(pk, sk):
    p = _derive_key.ristretto255_dh(pk, sk)
    return Py32LengthKey(p.key)

_derive_key.ristretto255_derive_secret_key.argtypes = [SecretKey, Random, Random]
_derive_key.ristretto255_derive_secret_key.restype = Keypair

def ristretto255_derive_secret_key(sk, i, r):
    return _derive_key.ristretto255_derive_secret_key(sk, i, r)
    # return Py32LengthKey(p.key)

_derive_key.ristretto255_derive_public_key.argtypes = [PublicKey, Random, Random]
_derive_key.ristretto255_derive_public_key.restype = Keypair

def ristretto255_derive_public_key(pk, i, r):
    return _derive_key.ristretto255_derive_public_key(pk, i, r)

def _main():
    import secrets
    import numpy as np
    seed1 = secrets.token_bytes(32)
    kp1 = ristretto255_key_gen_from_seed(seed1)

    seed2 = secrets.token_bytes(32)
    kp2 = ristretto255_key_gen_from_seed(seed2)
    res1 = ristretto255_dh(kp1.public_key, kp2.secret_key)
    res2 = ristretto255_dh(kp2.public_key, kp1.secret_key)

    kp_sub1 = ristretto255_derive_secret_key(kp1.secret_key, kp1.random_code, kp1.random_code)
    kp_sub2 = ristretto255_derive_public_key(kp1.public_key, kp1.random_code, kp1.random_code)

    print(bytes(kp_sub1.public_key.key))
    print(bytes(kp_sub2.public_key.key))
    print(bytes(kp_sub1.public_key.key) == bytes(kp_sub2.public_key.key))

if __name__ == '__main__':
    # import secrets
    # seed1 = secrets.token_bytes(32)
    # kp1 = ristretto255_key_gen_from_seed(seed1)

    # sk = bytes(kp1.secret_key.key)
    # print(type(sk))

    for _ in range(10):
        _main()
