from typing import Optional

from wizproxy.crypto import AesContext, KeyChain
from wizproxy.proto import (Bytes, EncryptedMessage, Frame, SignedMessage,
                            SocketAddress)
from wizproxy.proto.bytes import U32

from .challenges import ClientSig, process_challenge


def _extract_signed_message(raw: bytes) -> Optional[tuple[bytes]]:
    crypto_payload_len = U32.unpack_from(raw, 0xE)[0]
    if crypto_payload_len == 1:
        return None

    crypto_payload = raw[0x12 : 0x12 + crypto_payload_len]
    return crypto_payload[:-256], crypto_payload[-256:]


def _extract_encrypted_message(raw: bytes) -> Optional[tuple[bytes]]:
    crypto_payload_len = U32.unpack_from(raw, 0x10)[0]
    if crypto_payload_len == 1:
        return None

    return raw[0x15 : 0x15 + crypto_payload_len - 1]


class Session:
    """
    A proxied session between a client and server, managed by
    a shard.

    A session stores cryptographic state for the connection and
    attributes a unique ID to each client.

    :param client: The socket address of the connected client.
    :param server: The socket address of the connected server.
    :param sid: The Session ID of the client. Never changes.
    :param key_chain: The key chain for asymmetric crypto.
    """

    def __init__(
        self,
        client: SocketAddress,
        server: SocketAddress,
        sid: int,
        key_chain: KeyChain,
        client_sig: Optional[ClientSig],
    ):
        self.client = client
        self.server = server
        self.sid = sid
        self.key_chain = key_chain

        self.client_sig = client_sig
        self.challenge_response = None

        self.key_slot = 0xFF
        self.fnv_off = 0
        self.fnv_len = 0
        self.echo = 0

        self.client_aes = None
        self.server_aes = None

    def get_key_hash(self) -> int:
        return self.key_chain.hash_key_buf(self.fnv_off, self.fnv_len)

    def verify_key_hash(self, old: int):
        self.key_chain.verify_key_hash(self.fnv_off, self.fnv_len, old)

    def session_offer(self, frame: Frame):
        # Extract the signed crypto payload.
        raw = frame.payload
        if res := _extract_signed_message(raw):
            crypto_payload, signature = res
        else:
            return

        # Deserialize the message data.
        buf = Bytes(crypto_payload)
        message = SignedMessage.read(buf)
        buf.close()

        # Store session state we need to keep.
        self.key_slot = message.key_slot
        self.fnv_off, self.fnv_len = message.hash_region
        self.echo = message.echo

        # If we can, compute the challenge response so we can check with accept.
        self.challenge_response = process_challenge(self.client_sig, message)

        # Verify the original signature to detect outdated clients.
        self.key_chain.verify(self.key_slot, crypto_payload, signature)

        # Re-sign with our private key so the client will accept it.
        signature = self.key_chain.sign(self.key_slot, crypto_payload)

        # Reassemble the frame with the patched signature.
        new_payload = raw[: 0x12 + len(crypto_payload)] + signature + b"\x00"
        frame.payload = new_payload

    def session_accept(self, frame: Frame):
        # Extract and decrypt the crypto payload.
        raw = frame.payload
        if crypto_payload := _extract_encrypted_message(raw):
            crypto_payload = self.key_chain.decrypt(self.key_slot, crypto_payload)
        else:
            self.client_aes = None
            self.server_aes = None
            return

        # Deserialize the message data.
        buf = Bytes(crypto_payload)
        message = EncryptedMessage.read(buf)

        # Fix the FNV challenge for KI's public key buffer.
        self.verify_key_hash(message.key_hash)
        message.key_hash = self.get_key_hash()

        # Make sure the echo value matches the one from offer.
        if self.echo != message.echo:
            raise ValueError("echo value mismatch; algorithm changed?")

        # Make sure the challenge response we calculated matches.
        if self.challenge_response is not None:
            if self.challenge_response != message.challenge_answer:
                raise ValueError("challenge response mismatch; algorithm changed?")

        # Extract the symmetric encryption secrets.
        self.client_aes = AesContext.client(message.key, message.nonce)
        self.server_aes = AesContext.server(message.key, message.nonce)

        # Serialize the message data.
        buf.seek(0)
        message.write(buf)
        buf.truncate()

        # Re-encrypt the payload with KI's public key.
        crypto_payload = self.key_chain.encrypt(self.key_slot, buf.getvalue())
        buf.close()

        # Reassemble the frame with the patched payload.
        new_payload = raw[:0x15] + crypto_payload + b"\x00"
        frame.payload = new_payload
