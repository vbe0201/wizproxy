from struct import pack, unpack

from loguru import logger
from wizmsg.network import controls

from .aes import AesContext
from .key_chain import KeyChain


def human_bytes(raw: bytes) -> str:
    return raw.hex(" ").upper()


class Session:
    def __init__(self, sid: int, key_chain: KeyChain):
        self.sid = sid
        self.key_chain = key_chain

        self.key_slot = 0xFF

        self.fnv_off = 0
        self.fnv_len = 0

        self.client_aes = None
        self.server_aes = None

    def _extract_signed_message(self, raw: bytes) -> bytes:
        crypto_payload_len = unpack("<I", raw[0x16 : 0x16 + 4])[0] - 256
        return raw[0x1A : 0x1A + crypto_payload_len]

    def _extract_encrypted_message(self, raw: bytes) -> bytes:
        crypto_payload_len = unpack("<I", raw[0x18 : 0x18 + 4])[0] - 1
        return self.key_chain.decrypt(
            self.key_slot, raw[0x1D : 0x1D + crypto_payload_len]
        )

    def _make_key_hash(self) -> int:
        return self.key_chain.hash_key_buf(self.fnv_off, self.fnv_len)

    def session_offer(self, offer: controls.SessionOffer, raw: bytes) -> bytes:
        # Extract the signed crypto payload.
        crypto_payload = self._extract_signed_message(raw)
        challenge_type = offer.crypto_challenge[0x4]

        # Store the session state we need to keep.
        self.key_slot = offer.crypto_key_slot
        if challenge_type == 0xF1:
            fnv_off, fnv_len = unpack("<HH", offer.crypto_challenge[:0x4])
            self.fnv_off = fnv_off
            self.fnv_len = fnv_len
        else:
            raise RuntimeError(f"Unknown crypto challenge type: {challenge_type}")

        # Sign with our private key so the client will accept it.
        sig = self.key_chain.sign(self.key_slot, crypto_payload)

        # Compose a new frame with the patched signature.
        return raw[: 0x1A + len(crypto_payload)] + sig + b"\x00"

    def session_accept(self, raw: bytes) -> bytes:
        # We receive a public key encrypted Session Accept frame.
        # First, extract and decrypt it for working with it.
        crypto_payload = bytearray(self._extract_encrypted_message(raw))

        # Fix the FNV challenge for KI's public key buffer.
        crypto_payload[0x1:0x5] = pack("<I", self._make_key_hash())

        # Extract the symmetric encryption secrets.
        key = crypto_payload[-0x20:-0x10]
        nonce = crypto_payload[-0x10:]
        logger.info(
            f"Exfiltrated AES key ({human_bytes(key)}) and nonce ({human_bytes(nonce)})"
        )

        # Build crypto contexts for use with client and server.
        self.client_aes = AesContext.client(key, nonce)
        self.server_aes = AesContext.server(key, nonce)

        # Re-encrypt the payload with KI's public key and reassemble frame.
        crypto_payload = self.key_chain.encrypt(self.key_slot, crypto_payload)

        return raw[:0x1D] + crypto_payload + b"\x00"
