from struct import unpack
from typing import Optional

from .aes import AesContext
from .key_chain import KeyChain
from .proto import Bytes, EncryptedMessage, SignedMessage


class Session:
    """
    A client session to a proxy middleman.

    A session stores cryptographic state for the connection and
    attributes a unique ID to each client to tell them apart.

    :param sid: The session ID of the client. Never changes.
    :param key_chain: The :class:`KeyChain` for asymmetric crypto.
    """

    def __init__(self, sid: int, key_chain: KeyChain):
        self.sid = sid
        self.key_chain = key_chain

        self.key_slot = 0xFF

        self.fnv_off = 0
        self.fnv_len = 0

        self.client_aes = None
        self.server_aes = None

    def _extract_signed_message(self, raw: bytes) -> Optional[tuple[bytes, bytes]]:
        crypto_payload_len = unpack("<I", raw[0xE:0x12])[0]
        if crypto_payload_len == 1:
            return None

        crypto_payload = raw[0x12 : 0x12 + crypto_payload_len]
        return crypto_payload[:-256], crypto_payload[-256:]

    def _extract_encrypted_message(self, raw: bytes) -> Optional[bytes]:
        crypto_payload_len = unpack("<I", raw[0x10:0x14])[0] - 1
        if crypto_payload_len == 1:
            return None

        return raw[0x15 : 0x15 + crypto_payload_len]

    def _make_key_hash(self) -> int:
        return self.key_chain.hash_key_buf(self.fnv_off, self.fnv_len)

    def session_offer(self, raw: bytes) -> bytes:
        # Extract the signed crypto payload.
        if res := self._extract_signed_message(raw):
            crypto_payload, signature = res
        else:
            return raw

        # Deserialize the message data.
        bytes = Bytes(crypto_payload)
        message = SignedMessage.read(bytes)

        # Store session state we need to keep.
        self.key_slot = message.key_slot
        if message.challenge_type == 0xF1:
            fnv_off, fnv_len = message.hash_region
            self.fnv_off = fnv_off
            self.fnv_len = fnv_len
        else:
            raise RuntimeError(f"Unknown crypto challenge: {message.challenge_type}")

        # Verify the original signature to detect outdated clients.
        self.key_chain.verify(self.key_slot, crypto_payload, signature)

        # Re-sign with our private key so the client will accept it.
        signature = self.key_chain.sign(self.key_slot, crypto_payload)

        # Reassemble the frame with the patched signature.
        return raw[: 0x12 + len(crypto_payload)] + signature + b"\x00"

    def session_accept(self, raw: bytes) -> bytes:
        # Extract the encrypted payload and decrypt it.
        if crypto_payload := self._extract_encrypted_message(raw):
            crypto_payload = self.key_chain.decrypt(self.key_slot, crypto_payload)
        else:
            self.client_aes = None
            self.server_aes = None
            return raw

        # Deserialize the message data.
        bytes = Bytes(crypto_payload)
        message = EncryptedMessage.read(bytes)

        # Fix the FNV challenge for KI's public key buffer.
        message.key_hash = self._make_key_hash()

        # Extract the symmetric encryption secrets.
        self.client_aes = AesContext.client(message.key, message.nonce)
        self.server_aes = AesContext.server(message.key, message.nonce)

        # Serialize the message data.
        bytes.seek(0)
        message.write(bytes)

        # Re-encrypt the payload with KI's public key.
        crypto_payload = self.key_chain.encrypt(self.key_slot, bytes.getvalue())

        # Reassemble the frame with the patched payload.
        return raw[:0x15] + crypto_payload + b"\x00"
