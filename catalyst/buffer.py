from struct import unpack
from typing import Optional

from .aes import AesContext


def is_plaintext_frame(raw: bytes) -> bool:
    return raw[1] == 0xF0 and raw[0] == 0x0D


def is_large_frame(raw: bytes) -> bool:
    return len(raw) >= 0x8000


class PacketBuffer:
    def __init__(self):
        self.buf = b""
        self.buf_len = 0

        # State for the currently polled packet.
        self._encrypted = False
        self._header = None
        self._frame_size = 0

    def add_packet(self, data: bytes):
        self.buf += data
        self.buf_len += len(data)

    def poll_frame(self, ctx: AesContext | None) -> Optional[tuple[bool, bytes]]:
        if self.buf_len < 8:
            return None

        # Check if we already started breaking down a frame. If not,
        # consume its header and determine if it's encrypted.
        if self._header is None:
            self._encrypted = not (ctx is None or is_plaintext_frame(self.buf))
            self._header = self.buf[:8]

            if self._encrypted:
                self._header = ctx.decrypt(self._header)  # type:ignore

            magic, size, large_size = unpack("<HHI", self._header)

            # Validate the header magic.
            if magic != 0xF00D:
                raise ValueError("received unsupported frame data")

            # Read the frame size to determine if we have enough data.
            self._frame_size = size + 4
            if self._frame_size >= 0x8000:
                self._frame_size = large_size + 8

        # If we don't have enough data yet, wait for more.
        if self.buf_len < self._frame_size:
            return None

        # Extract the frame and decrypt it, if necessary.
        frame = self.buf[:self._frame_size]
        if self._encrypted:
            frame = self._header + ctx.decrypt(frame[8:])  # type:ignore

        # Keep the remainder for the next round of processing.
        self.buf = self.buf[self._frame_size:]
        self.buf_len -= self._frame_size
        self._header = None

        return self._encrypted, frame
