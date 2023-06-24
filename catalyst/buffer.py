from typing import Optional

from wizmsg import ByteInterface

from .aes import AesContext


def is_plaintext_frame(raw: bytes) -> bool:
    return raw[1] == 0xF0 and raw[0] == 0x0D


def is_large_frame(raw: bytes) -> bool:
    return len(raw) >= 0x8000


class PacketBuffer:
    def __init__(self):
        self._buf = bytearray()

    def add_packet(self, data: bytes):
        self._buf.extend(data)

    def poll_frame(self, ctx: AesContext | None) -> Optional[tuple[bool, bytes]]:
        if len(self._buf) < 8:
            return None

        encrypted = not (ctx is None or is_plaintext_frame(self._buf))

        # Before we start reading, make sure the first bytes of
        # an encrypted frame are in plaintext. Every frame has
        # at least 8 bytes, so this is good enough for us.
        if encrypted:
            self._buf[0:8] = ctx.decrypt(self._buf[0:8])  # type:ignore

        reader = ByteInterface(self._buf)

        magic = reader.unsigned2()
        if magic != 0xF00D:
            raise ValueError("received unsupported frame data")

        size = reader.unsigned2() + 4
        if size >= 0x8000:
            size = reader.unsigned4() + 8

        # If we don't have enough data yet, wait for more.
        if len(self._buf) < size:
            return None

        # Extract the frame and decrypt it, if necessary.
        frame = self._buf[:size]
        if encrypted:
            frame = self._buf[:8] + ctx.decrypt(frame[8:])  # type:ignore

        # Keep the remainder for the next round of processing.
        self._buf = self._buf[size:]

        return encrypted, frame
