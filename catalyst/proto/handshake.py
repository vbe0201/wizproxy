from dataclasses import dataclass
from struct import unpack
from typing import Self

from .bytes import Bytes


@dataclass
class SignedMessage:
    """The cryptographic message portion of Session Offer."""

    flags: int
    key_slot: int
    key_mask: int
    challenge: bytes
    nonce: int

    @classmethod
    def read(cls, buf: Bytes) -> Self:
        flags = buf.u8()
        key_slot = buf.u8()
        key_mask = buf.u8()
        challenge_len = buf.u8()
        challenge = buf.read(challenge_len)
        nonce = buf.u32()

        return cls(flags, key_slot, key_mask, challenge, nonce)

    def write(self, buf: Bytes) -> int:
        written = 0

        written += buf.write_u8(self.flags)
        written += buf.write_u8(self.key_slot)
        written += buf.write_u8(self.key_mask)
        written += buf.write_u8(len(self.challenge))
        written += buf.write(self.challenge)
        written += buf.write_u32(self.nonce)

        return written

    @property
    def hash_region(self) -> tuple[int, int]:
        return unpack("<HH", self.challenge[:4])

    @property
    def challenge_type(self) -> int:
        return self.challenge[4]


@dataclass
class EncryptedMessage:
    """The cryptographic message portion of Session Accept."""

    flags: int
    key_hash: int
    challenge_answer: int
    echo: int
    timestamp: int
    key: bytes
    nonce: bytes

    @classmethod
    def read(cls, buf: Bytes) -> Self:
        flags = buf.u8()
        key_hash = buf.u32()
        answer = buf.u32()
        echo = buf.u32()
        timestamp = buf.u32()
        key = buf.read(16)
        nonce = buf.read(16)

        return cls(flags, key_hash, answer, echo, timestamp, key, nonce)

    def write(self, buf: Bytes) -> int:
        written = 0

        written += buf.write_u8(self.flags)
        written += buf.write_u32(self.key_hash)
        written += buf.write_u32(self.challenge_answer)
        written += buf.write_u32(self.echo)
        written += buf.write_u32(self.timestamp)
        written += buf.write(self.key)
        written += buf.write(self.nonce)

        return written
