# Cryptographic operations for the Noise handshake, limited to WireGuard.
# Author: Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

import hashlib
import hmac

# Not a public symbol, but exactly what I need.
from nacl.bindings import crypto_scalarmult_base, crypto_scalarmult, \
    crypto_aead_chacha20poly1305_ietf_encrypt, \
    crypto_aead_chacha20poly1305_ietf_decrypt


def hashfn(data):
    return hashlib.blake2s(data).digest()


def hkdf(salt, ikm, n):
    assert n in (1, 2, 3)
    ts = []
    prk = hmac.new(salt, ikm, digestmod=hashlib.blake2s).digest()
    prk_hash = hmac.new(prk, digestmod=hashlib.blake2s)
    t = b''
    for i in range(1, n + 1):
        prk_hash_i = prk_hash.copy()
        prk_hash_i.update(t + i.to_bytes(1, 'big'))
        t = prk_hash_i.digest()
        ts.append(t)
    return ts[0] if n == 1 else tuple(ts)


def aead_encrypt(key, nonce, plaintext, aad):
    nonce = b'\0\0\0\0' + nonce.to_bytes(8, 'little')
    return crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def aead_decrypt(key, nonce, ciphertext, aad):
    nonce = b'\0\0\0\0' + nonce.to_bytes(8, 'little')
    return crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)


def _to_bytes(x):
    if type(x) == bytes:
        return x
    if hasattr(x, '__bytes__'):
        return bytes(x)
    raise AssertionError(f'Unexpected type: {x!r}')


class NoiseWG:
    def __init__(self, h=None, ck=None):
        if not h and not ck:
            ck = hashfn(b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s')
            h = hashfn(ck + b'WireGuard v1 zx2c4 Jason@zx2c4.com')
        self.h = h
        self.ck = ck
        self.k = None

    def mix_hash(self, data):
        self.h = hashfn(self.h + _to_bytes(data))

    def mix_key(self, key):
        self.ck = hkdf(self.ck, _to_bytes(key), 1)

    def mix_key_and_hash(self, key):
        self.ck, temp_h, self.k = hkdf(self.ck, _to_bytes(key), 3)
        self.mix_hash(temp_h)

    def mix_dh(self, priv, pub):
        # XXX unfortunately this fails for public keys such as 0 and 1 because
        # libsodium ref10 implementation rejects some small-order points.
        sk, pk = _to_bytes(priv), _to_bytes(pub)
        secret = crypto_scalarmult(sk, pk)
        self.ck, self.k = hkdf(self.ck, secret, 2)

    def encrypt_and_hash(self, data, nonce=0):
        assert self.k
        data = _to_bytes(data)
        enc = aead_encrypt(self.k, nonce, data, self.h)
        self.mix_hash(enc)
        self.k = None
        return enc

    def decrypt_and_hash(self, data, nonce=0):
        assert self.k
        assert data
        dec = aead_decrypt(self.k, nonce, data, self.h)
        self.mix_hash(data)
        self.k = None
        return dec

    def split(self):
        TsendI, TrecvI = hkdf(self.ck, b'', 2)
        self.ck = None
        return TsendI, TrecvI

    def copy(self):
        return NoiseWG(self.h, self.ck)
