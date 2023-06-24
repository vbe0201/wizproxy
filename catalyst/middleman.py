from collections import namedtuple

import trio
from loguru import logger

SocketAddress = namedtuple("SocketAddress", ("ip", "port"))


class MiddleMan:
    def __init__(self, name: str):
        self.name = name

    async def _client_task(self, stream: trio.SocketStream, peer: trio.SocketStream):
        async for packet in stream:
            logger.info(f"[C -> S] {packet.hex(' ').upper()}")
            await peer.send_all(packet)

    async def _server_task(self, stream: trio.SocketStream, peer: trio.SocketStream):
        async for packet in stream:
            logger.info(f"[S -> C] {packet.hex(' ').upper()}")
            await peer.send_all(packet)

    async def run(self, remote: SocketAddress):
        logger.info(f"[{self.name}] Spawning middleman to {remote}...")

        async def accept_tcp_client(stream: trio.SocketStream):
            outward = await trio.open_tcp_stream(*remote)
            logger.info(f"[{self.name}] Client {stream.socket.getsockname()} connected")

            try:
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(self._client_task, stream, outward)
                    nursery.start_soon(self._server_task, outward, stream)

            except* trio.BrokenResourceError:
                # We were pranked by a client disconnecting unexpectedly.
                # In that case, we shall just ignore it without bringing
                # the whole middleman server down.
                pass

        await trio.serve_tcp(accept_tcp_client, remote.port)
