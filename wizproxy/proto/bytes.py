import io
import struct
from typing import Any

U8 = struct.Struct("B")
I8 = struct.Struct("b")
U16 = struct.Struct("<H")
I16 = struct.Struct("<h")
U32 = struct.Struct("<I")
I32 = struct.Struct("<i")
U64 = struct.Struct("<Q")
F32 = struct.Struct("<f")
F64 = struct.Struct("<d")


class Bytes(io.BytesIO):
    """
    Provides reading and writing support for structured binary data.

    All operations assume little-endian byte ordering.
    """

    def load_frame(self, raw: bytes):
        self.seek(0)
        self.write(raw)
        self.truncate()

    def read_struct(self, s: struct.Struct) -> Any:
        value = s.unpack(self.read(s.size))
        return value[0] if len(value) == 1 else value

    def write_struct(self, s: struct.Struct, *args) -> int:
        packed = s.pack(*args)
        return self.write(packed)

    def u8(self) -> int:
        return self.read_struct(U8)

    def write_u8(self, v: int) -> int:
        return self.write_struct(U8, v)

    def i8(self) -> int:
        return self.read_struct(I8)

    def write_i8(self, v: int) -> int:
        return self.write_struct(I8, v)

    def u16(self) -> int:
        return self.read_struct(U16)

    def write_u16(self, v: int) -> int:
        return self.write_struct(U16, v)

    def i16(self) -> int:
        return self.read_struct(I16)

    def write_i16(self, v: int) -> int:
        return self.write_struct(I16, v)

    def u32(self) -> int:
        return self.read_struct(U32)

    def write_u32(self, v: int) -> int:
        return self.write_struct(U32, v)

    def i32(self) -> int:
        return self.read_struct(I32)

    def write_i32(self, v: int) -> int:
        return self.write_struct(I32, v)

    def u64(self) -> int:
        return self.read_struct(U64)

    def write_u64(self, v: int) -> int:
        return self.write_struct(U64, v)

    def f32(self) -> float:
        return self.read_struct(F32)

    def write_f32(self, v: float) -> int:
        return self.write_struct(F32, v)

    def f64(self) -> float:
        return self.read_struct(F64)

    def write_f64(self, v: float) -> int:
        return self.write_struct(F64, v)

    def string(self) -> bytes:
        size = self.u16()
        return self.read(size)

    def write_string(self, data: bytes) -> int:
        written = 0

        written += self.write_u16(len(data))
        written += self.write(data)

        return written

    def wstr(self) -> str:
        size = self.u16()
        return self.read(size * 2).decode("utf-16-le")

    def write_wstr(self, data: str) -> int:
        raw = data.encode("utf-16-le")
        written = 0

        written += self.write_u16(len(data))
        written += self.write(raw)

        return written
