from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Iterable

from .bytes import Bytes

_DML_DECODE_LOOKUP = [
    (Bytes.i8, Bytes.write_i8),
    (Bytes.u8, Bytes.write_u8),
    (Bytes.u16, Bytes.write_u16),
    (Bytes.i32, Bytes.write_i32),
    (Bytes.u32, Bytes.write_u32),
    (Bytes.u64, Bytes.write_u64),
    (Bytes.string, Bytes.write_string),
    (Bytes.wstr, Bytes.write_wstr),
    (Bytes.f32, Bytes.write_f32),
    (Bytes.f64, Bytes.write_f64),
]


class Type(IntEnum):
    """Enumeration of supported DML types."""

    BYT = 0
    UBYT = 1
    USHRT = 2
    INT = 3
    UINT = 4
    GID = 5
    STR = 6
    WSTR = 7
    FLT = 8
    DBL = 9


@dataclass
class Layout:
    """Describes the data layout of a DML message."""

    layout: Iterable[tuple[str, Type]]

    def encode(self, msg: dict[str, Any]) -> bytes:
        buf = Bytes()

        for name, typ in self.layout:
            value = msg[name]
            _, encode = _DML_DECODE_LOOKUP[typ]

            encode(buf, value)

        return buf.getvalue()

    def decode(self, raw: bytes) -> dict[str, Any]:
        buf = Bytes(raw)
        msg = {}

        for name, typ in self.layout:
            decode, _ = _DML_DECODE_LOOKUP[typ]

            msg[name] = decode(buf)

        return msg
