from dataclasses import dataclass, field
from typing import Optional, Self

from .bytes import Bytes


@dataclass
class Frame:
    """
    Parsed representation of a KingsIsle network frame.

    The payload portion needs implementation-defined handling
    depending on whether it is a control or data frame. It is
    not parsed by default.
    """

    original: bytes

    opcode: Optional[int]
    service_id: Optional[int]
    order: Optional[int]
    payload: bytes

    # Controls whether a frame needs to be reserialized after a change.
    dirty: bool = field(default=False)

    @classmethod
    def read(cls, buf: Bytes) -> Self:
        buf.seek(0)
        original = buf.getvalue()

        assert buf.u16() == 0xF00D

        size = buf.u16()
        if size >= 0x8000:
            size = buf.u32()

        is_control = buf.u8() != 0
        opcode = buf.u8()
        buf.u16()  # Reserved.

        if is_control:
            service_id, order = None, None
            payload = buf.read(size - 4)
        else:
            service_id = buf.u8()
            order = buf.u8()
            payload_len = buf.u16()
            payload = buf.read(payload_len - 4)
            buf.u8()  # Trailing null byte.

        return cls(original, opcode if is_control else None, service_id, order, payload)

    def write(self, buf: Bytes) -> int:
        buf.seek(0)

        written = 0
        payload_len = len(self.payload)

        size = 4 + payload_len
        if self.opcode is None:
            size += 5

        written += buf.write_u16(0xF00D)
        if size < 0x8000:
            written += buf.write_u16(size)
        else:
            written += buf.write_u16(0x8000)
            written += buf.write_u32(size)

        is_control = self.opcode is not None

        written += buf.write_u8(1 if is_control else 0)
        written += buf.write_u8(self.opcode or 0)
        written += buf.write_u16(0)

        if is_control:
            written += buf.write(self.payload)
        else:
            written += buf.write_u8(self.service_id)
            written += buf.write_u8(self.order)
            written += buf.write_u16(payload_len + 4)
            written += buf.write(self.payload)
            written += buf.write_u8(0)

        buf.truncate()
        return written
