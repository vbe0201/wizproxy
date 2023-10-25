from base64 import b64decode
from typing import Any

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def fnv_1a(data: bytes) -> int:
    state = 0x811C9DC5
    for b in data:
        state ^= b
        state *= 0x01000193
        state &= 0xFFFF_FFFF

    return state


class KeyChain:
    """
    Key chain for managing asymmetric keys.

    The foundation for proxying is the exfiltration of symmetric keys
    during the initial session handshake.

    This is accomplished by making the client use a control set of keys
    to encrypt its payload, then re-encrypt it with KI's keys before
    forwarding it to the server.

    Key material is obtained from ki-keyring project and the accepted
    format is the output JSONs it produces.

    :param ki_keys: KingsIsle public key material from a client.
    :param injected_keys: Private key material to injected client keys.
    """

    def __init__(self, ki_keys: dict[str, Any], injected_keys: dict[str, Any]):
        self.ki_key_buf = b64decode(ki_keys["raw"].encode())
        self.public_keys = [
            RSA.import_key(b64decode(key["public"].encode()))
            for key in ki_keys["decoded"]
        ]

        self.injected_key_buf = b64decode(injected_keys["raw"].encode())
        self.private_keys = [
            RSA.import_key(b64decode(key["private"].encode()))
            for key in injected_keys["decoded"]
        ]

    def hash_key_buf(self, offset: int, length: int) -> int:
        return fnv_1a(self.ki_key_buf[offset : offset + length])

    def verify_key_hash(self, offset: int, length: int, expected: int):
        buf_hash = fnv_1a(self.injected_key_buf[offset : offset + length])
        if buf_hash != expected:
            raise ValueError("key hash mismatch; algorithm changed?")

    def sign(self, key_slot: int, data: bytes) -> bytes:
        key = self.private_keys[key_slot]
        data_hash = SHA1.new(data)

        return pkcs1_15.new(key).sign(data_hash)

    def verify(self, key_slot: int, data: bytes, signature: bytes):
        key = self.public_keys[key_slot]
        data_hash = SHA1.new(data)

        pkcs1_15.new(key).verify(data_hash, signature)

    def encrypt(self, key_slot: int, data: bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.public_keys[key_slot])
        return cipher.encrypt(data)

    def decrypt(self, key_slot: int, data: bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.private_keys[key_slot])
        return cipher.decrypt(data)
