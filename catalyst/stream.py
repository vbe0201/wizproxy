from struct import unpack
from typing import Optional, Self

import trio

from .aes import AesContext, NONCE_SIZE, TAG_SIZE
from .session import Session


def is_plaintext_frame(raw: bytes) -> bool:
    return raw[1] == 0xF0 and raw[0] == 0x0D


def is_large_frame(size: int) -> bool:
    return size >= 0x8000


class SessionStream:
    """
    An asynchronous iterator over whole frames in a
    :class:`trio.SocketStream`.

    As the name suggests, these streams are tied to a specific
    session and one direction of processing.

    This class is responsible for buffering data from the socket
    until whole frames can be extracted out of it. Decryption is
    handled internally.
    """

    def __init__(self, stream: trio.SocketStream, session: Session, client: bool):
        self._stream = aiter(stream)
        self.session = session
        self.client = client

        self.buffer = PacketBuffer()

    def get_aes_context(self) -> Optional[AesContext]:
        if self.client:
            return self.session.client_aes
        else:
            return self.session.server_aes

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> tuple[bool, bytes]:
        while True:
            # If a frame is ready to be consumed, return it.
            if frame := self.buffer.poll_frame(self.get_aes_context()):
                return frame

            # Otherwise, wait for more stream data and try again.
            data = await anext(self._stream)
            self.buffer.feed(data)


class PacketBuffer:
    """
    Buffers raw TCP data and splits it into frames.

    At the core, users feed data in and poll for frames
    until they get None.
    """

    def __init__(self):
        self.buf = bytearray()
        self.buf_len = 0

        # State for the currently polled frame.
        self._header = None
        self._encrypted = False

    def feed(self, data: bytes):
        self.buf.extend(data)
        self.buf_len += len(data)

    def split_off(self, nbytes: int) -> bytes:
        data = self.buf[:nbytes]

        self.buf = self.buf[nbytes:]
        self.buf_len -= nbytes

        return data

    def required_bytes_to_decrypt(self, aes: AesContext | None, nbytes: int) -> int:
        if not self._encrypted:
            return nbytes

        chunk_size = aes.chunk_size  # type:ignore
        decrypted = aes.decrypted  # type:ignore

        overflows = 0
        remainder_until_rotation = chunk_size - decrypted
        if remainder_until_rotation <= nbytes:
            overflows = ((nbytes - remainder_until_rotation) // chunk_size) + 1

        return nbytes + ((TAG_SIZE + NONCE_SIZE) * overflows)

    def poll_header(self, aes: AesContext | None) -> Optional[bytes]:
        # Check if we already started breaking down a frame. If not,
        # consume its header and determine if it's encrypted.
        if self._header is None:
            # Make sure we have enough bytes to check the magic.
            if self.buf_len < 2:
                return None

            # Determine if the frame is encrypted.
            self._encrypted = not (aes is None or is_plaintext_frame(self.buf))

            # Make sure we have enough bytes to consume the frame header.
            header_bytes = self.required_bytes_to_decrypt(aes, 8)
            if self.buf_len < header_bytes:
                return None

            # Consume the header and store it. Also decrypt, if necessary.
            self._header = self.split_off(header_bytes)
            if self._encrypted:
                self._header = aes.decrypt(self._header)  # type:ignore

        return self._header

    def poll_frame(self, aes: AesContext | None) -> Optional[tuple[bool, bytes]]:
        # Read and decrypt the next frame's header or wait for more data.
        header = self.poll_header(aes)
        if header is None:
            return None

        # Unpack the data to make sure we can consume the frame.
        magic, size, large_size = unpack("<HHI", header)

        # Validate the header magic to make sure the data is valid.
        if magic != 0xF00D:
            raise ValueError("received unsupported frame data")

        # Unpack the size and compute how many bytes we still need
        # to consume, nonce rotations included.
        if is_large_frame(size):
            size = large_size
        else:
            # We already consumed the first 4 bytes of the body
            # prematurely to make sure our header is big enough.
            size -= 4
        size = self.required_bytes_to_decrypt(aes, size)

        # If we don't have enough data yet, wait for more.
        if self.buf_len < size:
            return None

        # Extract the frame body and decrypt it, if necessary.
        body = self.split_off(size)
        if self._encrypted:
            body = aes.decrypt(body)  # type:ignore

        self._header = None

        return self._encrypted, header + body
