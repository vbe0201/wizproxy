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
        self._key = key
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

    def _calculate_overhead(self, progress: int, step: int, nbytes: int) -> int:
        chunk_size = self.chunk_size
        block = chunk_size + step

        overflows = 0
        remainder_until_rotation = chunk_size - progress
        if remainder_until_rotation <= nbytes:
            overflows = ((nbytes - remainder_until_rotation) // block) + 1

        return (TAG_SIZE + NONCE_SIZE) * overflows

    def calculate_encryption_overhead(self, nbytes: int) -> int:
        overhead = self._calculate_overhead(self.encrypted, 0, nbytes)
        return nbytes + overhead

    def calculate_decryption_overhead(self, nbytes: int) -> int:
        overhead = self._calculate_overhead(self.decrypted, 0, nbytes)
        return nbytes + overhead

    def strip_decryption_overhead(self, nbytes: int) -> int:
        overhead = self._calculate_overhead(
            self.decrypted,
            TAG_SIZE + NONCE_SIZE,
            nbytes,
        )
        return nbytes - overhead

    def encrypt(self, data: bytes) -> bytearray:
        data_len = len(data)
        output = bytearray(self.calculate_encryption_overhead(data_len))

        # We have pre-allocated the entire `output` including any overhead
        # that may be created through nonce rotations. Now we use a view
        # to fill that buffer without needing any further allocations.
        output_view = memoryview(output)
        while data_len > 0:
            remaining = self.chunk_size - self.encrypted

            # Split the remaining data into what's part of the currently
            # processed chunk and what is remainder for the next round.
            current = data[:remaining]
            current_len = len(current)
            data = data[remaining:]

            # Encrypt the chunk and update processed bytes accordingly.
            self.encryptor.encrypt(current, output_view[:current_len])
            self.encrypted = (self.encrypted + current_len) % self.chunk_size
            output_view = output_view[current_len:]

            # If the chunk is finished, regenerate the AES context.
            # A MAC over all processed data and a new nonce are attached.
            if self.encrypted == 0:
                output_view[:TAG_SIZE] = self.encryptor.digest()
                self.encryptor = AES.new(
                    self._key,
                    AES.MODE_GCM,
                    nonce=get_random_bytes(NONCE_SIZE),
                )
                output_view[TAG_SIZE : TAG_SIZE + NONCE_SIZE] = self.encryptor.nonce

                output_view = output_view[TAG_SIZE + NONCE_SIZE :]

            data_len -= current_len

        return output

    def decrypt(self, data: bytes) -> bytearray:
        data_len = len(data)
        output = bytearray(self.strip_decryption_overhead(data_len))

        # We have pre-allocated the entire `output` except any overhead
        # that may be created through nonce rotations. Now we use a view
        # to fill that buffer without needing any further allocations.
        output_view = memoryview(output)
        while data_len > 0:
            remaining = self.chunk_size - self.decrypted

            # Split the remaining data into what's part of the currently
            # processed chunk and what is remainder for the next round.
            current = data[:remaining]
            current_len = len(current)
            data = data[remaining:]

            # Decrypt the chunk and update processed bytes accordingly.
            self.decryptor.decrypt(current, output_view[:current_len])
            self.decrypted = (self.decrypted + current_len) % self.chunk_size
            output_view = output_view[current_len:]

            # If the chunk is exhausted, regenerate the AES context.
            # A MAC over all processed data is verified and a new nonce is loaded.
            if self.decrypted == 0:
                self.decryptor.verify(data[:TAG_SIZE])
                self.decryptor = AES.new(
                    self._key,
                    AES.MODE_GCM,
                    nonce=data[TAG_SIZE : TAG_SIZE + NONCE_SIZE],
                )

                data = data[TAG_SIZE + NONCE_SIZE :]
                data_len -= TAG_SIZE + NONCE_SIZE

            data_len -= current_len

        return output
