from dataclasses import dataclass
from typing import Optional, Self

from .bytes import Bytes


@dataclass
class Frame:
    """
    Parsed representation of a KingsIsle network frame.

    The payload portion needs implementation-defined handling
    depending on whether it is a control or data frame.
    """

    opcode: Optional[int]
    service_id: Optional[int]
    order: Optional[int]
    payload: bytes

    @classmethod
    def read(cls, buf: Bytes) -> Self:
        buf.u16()

        size = buf.u16()
        if size >= 0x8000:
            size = buf.u32()

        is_control = buf.u8() != 0
        opcode = buf.u8()
        buf.u16()

        if is_control:
            service_id = None
            order = None
            payload = buf.read()
        else:
            service_id = buf.u8()
            order = buf.u8()
            payload_len = buf.u16()
            payload = buf.read(payload_len - 4)

        return cls(opcode if is_control else None, service_id, order, payload)

    def write(self, buf: Bytes) -> int:
        buf.seek(0)
        written = 0

        size = 4 + len(self.payload)
        if self.opcode is None:
            size += 5

        written += buf.write_u16(0xF00D)
        if size < 0x8000:
            written += buf.write_u16(size)
        else:
            written += buf.write_u16(0x8000)
            written += buf.write_u32(size)

        is_control = self.opcode is not None

        written += buf.write_u8(int(is_control))
        written += buf.write_u8(self.opcode or 0)
        written += buf.write_u16(0)

        if is_control:
            written += buf.write(self.payload)
        else:
            written += buf.write_u8(self.service_id)  # type:ignore
            written += buf.write_u8(self.order)  # type:ignore
            written += buf.write_u16(len(self.payload) + 4)
            written += buf.write(self.payload)
            written += buf.write_u8(0)

        buf.truncate()
        return written
