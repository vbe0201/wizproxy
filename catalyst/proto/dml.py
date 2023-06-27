from dataclasses import dataclass
from enum import Enum
from typing import Any

from .bytes import Bytes

_DML_DECODE_LOOKUP = [
    (Bytes.i8, Bytes.write_i8),
    (Bytes.u8, Bytes.write_u8),
    (Bytes.u16, Bytes.write_u16),
    (Bytes.i32, Bytes.write_i32),
    (Bytes.u32, Bytes.write_u32),
    (Bytes.string, Bytes.write_string),
    (Bytes.wstr, Bytes.write_wstr),
    (Bytes.f32, Bytes.write_f32),
    (Bytes.f64, Bytes.write_f64),
]


class Type(Enum):
    BYT = 0
    UBYT = 1
    USHRT = 2
    INT = 3
    UINT = 4
    STR = 5
    WSTR = 6
    FLT = 7
    DBL = 8


@dataclass
class Layout:
    layout: list[tuple[str, Type]]

    def encode(self, msg: dict[str, Any]) -> bytes:
        buf = Bytes()

        for name, typ in self.layout:
            value = msg[name]
            _, encode = _DML_DECODE_LOOKUP[typ.value]

            encode(buf, value)

        return buf.getvalue()

    def decode(self, raw: bytes) -> dict[str, Any]:
        buf = Bytes(raw)
        msg = {}

        for name, typ in self.layout:
            decode, _ = _DML_DECODE_LOOKUP[typ.value]

            msg[name] = decode(buf)

        return msg
