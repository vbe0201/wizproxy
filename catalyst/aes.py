from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CLIENT_CHUNK = 0x100 * AES.block_size
SERVER_CHUNK = 0x1000 * AES.block_size

NONCE_SIZE = AES.block_size
MAC_SIZE = NONCE_SIZE


class AesContext:
    def __init__(self, key: bytes, nonce: bytes, chunk_size: int):
        self.key = key
        self.chunk_size = chunk_size

        self.encryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
        self.encrypted = 0

        self.decryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
        self.decrypted = 0

    @classmethod
    def client(cls, key: bytes, nonce: bytes):
        return cls(key, nonce, CLIENT_CHUNK)

    @classmethod
    def server(cls, key: bytes, nonce: bytes):
        return cls(key, nonce, SERVER_CHUNK)

    def encrypt(self, data: bytes) -> bytes:
        output = b""

        data_len = len(data)
        while data_len > 0:
            remaining = self.chunk_size - self.encrypted

            # Split data into what is part of the current chunk and remainder.
            current = data[:remaining]
            data = data[remaining:]

            # Encrypt the data and update processed bytes accordingly.
            output += self.encryptor.encrypt(current)
            self.encrypted = (self.encrypted + len(current)) % self.chunk_size

            # If the current chunk is exhausted, generate a new AES context for
            # the next one.
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

            # Split data into what is part of the current chunk and remainder.
            current = data[:remaining]
            data = data[remaining:]

            # Decrypt the data and update processed bytes accordingly.
            output += self.decryptor.decrypt(current)
            self.decrypted = (self.decrypted + len(current)) % self.chunk_size

            # If the current chunk is exhausted, verify the MAC and regenerate
            # the AES context for the next one.
            if self.decrypted == 0:
                self.decryptor.verify(data[:MAC_SIZE])
                self.decryptor = AES.new(
                    self.key,
                    AES.MODE_GCM,
                    nonce=data[MAC_SIZE : MAC_SIZE + NONCE_SIZE],
                )

                data = data[MAC_SIZE + NONCE_SIZE :]
                data_len -= MAC_SIZE + NONCE_SIZE

            data_len -= len(current)

        return output
