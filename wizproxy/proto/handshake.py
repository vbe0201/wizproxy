from dataclasses import dataclass
from struct import Struct
from typing import Self

from .bytes import Bytes

_HASH = Struct("<HH")


@dataclass
class SignedMessage:
    """The cryptographic message portion of Session Offer."""

    flags: int
    key_slot: int
    key_mask: int
    challenge: bytes
    echo: int

    @classmethod
    def read(cls, buf: Bytes) -> Self:
        flags = buf.u8()
        key_slot = buf.u8()
        key_mask = buf.u8()
        challenge_len = buf.u8()
        challenge = buf.read(challenge_len)
        echo = buf.u32()

        return cls(flags, key_slot, key_mask, challenge, echo)

    def write(self, buf: Bytes) -> int:
        written = 0

        written += buf.write_u8(self.flags)
        written += buf.write_u8(self.key_slot)
        written += buf.write_u8(self.key_mask)
        written += buf.write_u8(len(self.challenge))
        written += buf.write(self.challenge)
        written += buf.write_u32(self.echo)

        return written

    @property
    def hash_region(self) -> tuple[int, int]:
        return _HASH.unpack_from(self.challenge)

    @property
    def challenge_type(self) -> int:
        return self.challenge[4]

    @property
    def challenge_buf(self) -> bytes:
        return self.challenge[5:]


@dataclass
class EncryptedMessage:
    """The cryptographic message portion of Session Accept."""

    _STRUCT = Struct("<BIIII16s16s")

    flags: int
    key_hash: int
    challenge_answer: int
    echo: int
    timestamp: int
    key: bytes
    nonce: bytes

    @classmethod
    def read(cls, buf: Bytes) -> Self:
        args = buf.read_struct(EncryptedMessage._STRUCT)
        return cls(*args)

    def write(self, buf: Bytes) -> int:
        return buf.write_struct(
            EncryptedMessage._STRUCT,
            self.flags,
            self.key_hash,
            self.challenge_answer,
            self.echo,
            self.timestamp,
            self.key,
            self.nonce,
        )
