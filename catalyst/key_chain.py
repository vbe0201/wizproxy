import json

from base64 import b64decode
from pathlib import Path

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
    def __init__(self, ki_keys_path: Path, injected_path: Path):
        with open(ki_keys_path, encoding="utf-8") as f:
            ki_keys = json.load(f)

            self.key_buf = b64decode(ki_keys["raw"].encode())
            self.public_keys = [
                RSA.import_key(b64decode(key["public"].encode()))
                for key in ki_keys["decoded"]
            ]

        with open(injected_path, encoding="utf-8") as f:
            injected = json.load(f)

            self.private_keys = [
                RSA.import_key(b64decode(key["private"].encode()))
                for key in injected["decoded"]
            ]

    def hash_key_buf(self, offset: int, length: int) -> int:
        return fnv_1a(self.key_buf[offset : offset + length])

    def sign(self, key_slot: int, data: bytes) -> bytes:
        key = self.private_keys[key_slot]
        data_hash = SHA1.new(data)

        return pkcs1_15.new(key).sign(data_hash)

    def encrypt(self, key_slot: int, data: bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.public_keys[key_slot])
        return cipher.encrypt(data)

    def decrypt(self, key_slot: int, data: bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.private_keys[key_slot])
        return cipher.decrypt(data)
