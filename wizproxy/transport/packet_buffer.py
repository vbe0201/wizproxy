from enum import IntEnum
from struct import Struct
from typing import Optional

from wizproxy.crypto import AesContext

FRAME_HEADER = Struct("<HHI")


class State(IntEnum):
    EMPTY = 0
    GOT_ENCRYPTED_FOOD = 1
    GOT_FOOD = 2


def is_plaintext_frame(raw: memoryview) -> bool:
    return raw[1] == 0xF0 and raw[0] == 0x0D


def is_large_frame(size: int) -> bool:
    return size >= 0x8000


class PacketBuffer:
    """
    Buffers incoming TCP data and splits it into protocol frames.

    This class is meant to be reusable; each connection should
    maintain an instance and reuse the memory to reduce the
    number of allocations in the program.
    """

    def __init__(self):
        self.buf = bytearray()
        self.buf_len = 0

        self._state = State.EMPTY
        self._food = None

    def feed(self, data: bytes):
        self.buf.extend(data)
        self.buf_len += len(data)

    def split_off(self, nbytes: int) -> bytes:
        data = self.buf[:nbytes]

        self.buf = self.buf[nbytes:]
        self.buf_len -= nbytes

        return data

    def _required_bytes(self, aes: Optional[AesContext], nbytes: int) -> int:
        if aes is not None:
            return aes.calculate_decryption_overhead(nbytes)
        else:
            return nbytes

    def _poll_header(self, aes: Optional[AesContext]):
        if self._state == State.EMPTY:
            # Make sure we have enough bytes to consume the frame header.
            food_bytes = self._required_bytes(aes, 8)
            if self.buf_len < food_bytes:
                return

            # Determine if the frame is encrypted by some magic header bytes.
            encrypted = aes is not None and not is_plaintext_frame(self.buf)

            self._food = self.split_off(food_bytes)
            if encrypted:
                self._food = aes.decrypt(self._food)
                self._state = State.GOT_ENCRYPTED_FOOD
            else:
                self._state = State.GOT_FOOD

    def poll_frame(self, aes: Optional[AesContext]) -> Optional[tuple[bool, bytes]]:
        # Read and decrypt the next frame's header, or wait for more data.
        self._poll_header(aes)
        if self._state == State.EMPTY:
            return None

        # Unpack the header data and make sure we can consume the frame.
        magic, size, large_size = FRAME_HEADER.unpack(self._food)

        # Validate the header magic to make sure the data is valid.
        if magic != 0xF00D:
            raise ValueError("received unsupported frame data")

        # Unpack the size and compute how many bytes we still need to consume.
        if is_large_frame(size):
            size = large_size
        else:
            # We already consumed the first 4 bytes of the body prematurely
            # to make sure our header is big enough.
            size -= 4
        size = self._required_bytes(aes, size)

        # If we don't have enough data yet, wait for more.
        if self.buf_len < size:
            return None

        # Extract the frame body and decrypt it, if necessary.
        body = self.split_off(size)
        encrypted = self._state == State.GOT_ENCRYPTED_FOOD
        if encrypted:
            body = aes.decrypt(body)

        self._state = State.EMPTY

        return encrypted, self._food + body
