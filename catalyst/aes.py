from typing import Self

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CLIENT_CHUNK = 0x100 * AES.block_size
SERVER_CHUNK = 0x1000 * AES.block_size

NONCE_SIZE = AES.block_size
TAG_SIZE = AES.block_size


class AesContext:
    """
    Symmetric AES-GCM processing context.

    After the session handshake, all data will be sent encrypted. Each peer
    maintains separate states for sending and receiving packets, which is
    replicated by the encrypt/decrypt routines.

    After construction, the class manages its own key material and will
    rotate nonces as mandated during data processing.

    :param key: The 16-byte AES encryption key.
    :param nonce: The 16-byte GCM nonce.
    :param chunk_size: The size of each chunk before nonce rotation.
    """

    def __init__(self, key: bytes, nonce: bytes, chunk_size: int):
        self.key = key
        self.chunk_size = chunk_size

        self.encryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
        self.encrypted = 0

        self.decryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
        self.decrypted = 0

    @classmethod
    def client(cls, key: bytes, nonce: bytes) -> Self:
        return cls(key, nonce, CLIENT_CHUNK)

    @classmethod
    def server(cls, key: bytes, nonce: bytes) -> Self:
        return cls(key, nonce, SERVER_CHUNK)

    def encrypt(self, data: bytes) -> bytes:
        output = b""

        data_len = len(data)
        while data_len > 0:
            remaining = self.chunk_size - self.encrypted

            # Split data into current chunk and remainder.
            current = data[:remaining]
            data = data[remaining:]

            # Encrypt the chunk and update processed bytes accordingly.
            output += self.encryptor.encrypt(current)
            self.encrypted = (self.encrypted + len(current)) % self.chunk_size

            # If the chunk is exhausted, regenerate the AES context.
            # A MAC over all processed data and a new nonce are attached.
            if self.encrypted == 0:
                output += self.encryptor.digest()
                self.encryptor = AES.new(
                    self.key,
                    AES.MODE_GCM,
                    nonce=get_random_bytes(NONCE_SIZE),
                )
                output += self.encryptor.nonce

            data_len -= len(current)

        return output

    def decrypt(self, data: bytes) -> bytes:
        output = b""

        data_len = len(data)
        while data_len > 0:
            remaining = self.chunk_size - self.decrypted

            # Split data into current chunk and remainder.
            current = data[:remaining]
            data = data[remaining:]

            # Decrypt the chunk and update processed bytes accordingly.
            output += self.decryptor.decrypt(current)
            self.decrypted = (self.decrypted + len(current)) % self.chunk_size

            # If the chunk is exhausted, regenerate the AES context.
            # A MAC over all processed data is verified and a new nonce is loaded.
            if self.decrypted == 0:
                self.decryptor.verify(data[:TAG_SIZE])
                self.decryptor = AES.new(
                    self.key,
                    AES.MODE_GCM,
                    nonce=data[TAG_SIZE : TAG_SIZE + NONCE_SIZE],
                )

                data = data[TAG_SIZE + NONCE_SIZE :]
                data_len -= TAG_SIZE + NONCE_SIZE

            data_len -= len(current)

        return output
