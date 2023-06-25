from struct import unpack
from typing import Optional

from .aes import AesContext


def is_plaintext_frame(raw: bytes) -> bool:
    return raw[1] == 0xF0 and raw[0] == 0x0D


def is_large_frame(raw: bytes) -> bool:
    return len(raw) >= 0x8000


class PacketBuffer:
    def __init__(self):
        self._buf = bytearray()
        self._buf_len = 0

        # State for the currently polled frame.
        self._encrypted = False
        self._header = None

    def add_packet(self, data: bytes):
        self._buf.extend(data)
        self._buf_len += len(data)

    def poll_frame(self, ctx: AesContext | None) -> Optional[tuple[bool, bytes]]:
        if self._buf_len < 8:
            return None

        # Check if we already started breaking down a frame. If not,
        # consume its header and determine if it's encrypted.
        if self._header is None:
            self._encrypted = not (ctx is None or is_plaintext_frame(self._buf))
            self._header = self._buf[:8]

            if self._encrypted:
                self._header = ctx.decrypt(self._header)  # type:ignore

        magic, size, large_size = unpack("<HHI", self._header)

        if magic != 0xF00D:
            raise ValueError("received unsupported frame data")

        if size >= 0x8000:
            size = large_size + 8
        else:
            size += 4

        # If we don't have enough data yet, wait for more.
        if self._buf_len < size:
            return None

        # Extract the frame and decrypt it, if necessary.
        frame = self._buf[:size]
        if self._encrypted:
            frame = self._header + ctx.decrypt(frame[8:])  # type:ignore

        # Keep the remainder for the next round of processing.
        self._buf = self._buf[size:]
        self._buf_len -= size
        self._header = None

        return self._encrypted, frame
