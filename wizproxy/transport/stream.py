from typing import Optional

import trio

from wizproxy.crypto import AesContext
from wizproxy.session import Session

from .packet_buffer import PacketBuffer

# Timeout is chosen so that it represents double the serverbound
# Keep Alive Rsp interval. If one party is too slow to send
# anything at all in that time, the connection is zombied.
TIMEOUT = 120.0


class FrameStream:
    """
    An asynchronous iterator over whole frames received from a
    :class:`trio.SocketStream`.

    As the name suggests, these streams are tied to a specific
    transport stream and enable one direction of processing.

    Implementation-wise, this class buffers data from a socket
    until a complete frame can be pulled out of it. Decryption
    is handled internally.
    """

    def __init__(self, stream: trio.SocketStream, session: Session, client: bool):
        self._stream = stream.__aiter__()

        self.session = session
        self.client = client

        self.buffer = PacketBuffer()

    @property
    def aes_context(self) -> Optional[AesContext]:
        if self.client:
            return self.session.client_aes
        else:
            return self.session.server_aes

    def __aiter__(self) -> "FrameStream":
        return self

    async def __anext__(self) -> tuple[bool, bytes]:
        while True:
            # If a frame is ready to be consumed, return it.
            if frame := self.buffer.poll_frame(self.aes_context):
                return frame

            # Otherwise, wait for more stream data and try again.
            with trio.fail_after(TIMEOUT):
                data = await self._stream.__anext__()
                self.buffer.feed(data)
