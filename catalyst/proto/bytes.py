import io
import struct
from typing import Any


class Bytes(io.BytesIO):
    """
    A :class:`io.BytesIO` with support for structured data.

    All operations assume little-endian byte ordering.
    """

    def _read_fmt(self, fmt: str) -> Any:
        size = struct.calcsize(fmt)
        unpacked = struct.unpack(fmt, self.read(size))

        return unpacked[0] if len(unpacked) == 1 else unpacked

    def _write_fmt(self, fmt: str, *args) -> int:
        packed = struct.pack(fmt, *args)
        return self.write(packed)

    def u8(self) -> int:
        return self._read_fmt("B")

    def write_u8(self, value: int) -> int:
        return self._write_fmt("B", value)

    def i8(self) -> int:
        return self._read_fmt("b")

    def write_i8(self, value: int) -> int:
        return self._write_fmt("b", value)

    def u16(self) -> int:
        return self._read_fmt("<H")

    def write_u16(self, value: int) -> int:
        return self._write_fmt("<H", value)

    def i16(self) -> int:
        return self._read_fmt("<h")

    def write_i16(self, value: int) -> int:
        return self._write_fmt("<h", value)

    def u32(self) -> int:
        return self._read_fmt("<I")

    def write_u32(self, value: int) -> int:
        return self._write_fmt("<I", value)

    def i32(self) -> int:
        return self._read_fmt("<i")

    def write_i32(self, value: int) -> int:
        return self._write_fmt("<i", value)

    def u64(self) -> int:
        return self._read_fmt("<Q")

    def write_u64(self, value: int) -> int:
        return self._write_fmt("<Q", value)

    def f32(self) -> float:
        return self._read_fmt("<f")

    def write_f32(self, value: float) -> int:
        return self._write_fmt("<f", value)

    def f64(self) -> float:
        return self._read_fmt("<d")

    def write_f64(self, value: float) -> int:
        return self._write_fmt("<d", value)

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
        return self.read(size).decode("utf-16-le")

    def write_wstr(self, data: str) -> int:
        raw = data.encode("utf-16-le")
        written = 0

        written += self.write_u16(len(raw))
        written += self.write(raw)

        return written
