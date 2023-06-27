import itertools
from collections import namedtuple
from struct import unpack

import trio
from loguru import logger

from .key_chain import KeyChain
from .session import Session

SocketAddress = namedtuple("SocketAddress", ("ip", "port"))


class Shard:
    """
    Representation of an individual server in the proxy.

    Each shard is bound to one specific game server and all clients
    that would normally connect to that server will connect to the
    shard instead.

    Shards are modeled as an actor system where the proxy supervises
    each shard. Shard actors talk to the proxy to spawn more siblings,
    as required during the processing of network packets.

    :param name: The human-readable name of the shard.
    :param key_chain: The :class:`KeyChain` for asymmetric crypto.
    :param proxy_tx: The channel for sending commands to the supervisor.
    :param command_rx: The channel for receiving commands from the outside.
    """

    def __init__(
        self,
        name: str,
        key_chain: KeyChain,
        proxy_tx: trio.abc.SendChannel[tuple[str, SocketAddress]],
        command_rx: trio.abc.ReceiveChannel[tuple[int, bytes]],
    ):
        self.name = name
        self.key_chain = key_chain
        self.proxy_tx = proxy_tx
        self.command_rx = command_rx

        self._id_generator = itertools.count()

    async def _client_task(
        self,
        session: Session,
        stream: trio.SocketStream,
        peer: trio.SocketStream,
    ):
        async for data in stream:
            magic, size = unpack("<HH", data[:4])
            if magic == 0xF00D and data[9 if size >= 0x8000 else 5] == 5:
                await peer.send_all(session.session_accept(data))
                continue

            dec = session.client_aes.decrypt(data)  # type:ignore
            logger.info(f"[C -> S] {dec.hex(' ').upper()}")

            await peer.send_all(data)

    async def _server_task(
        self,
        session: Session,
        stream: trio.SocketStream,
        peer: trio.SocketStream,
    ):
        async for data in stream:
            magic, size = unpack("<HH", data[:4])
            if magic == 0xF00D and data[9 if size >= 0x8000 else 5] == 0:
                await peer.send_all(session.session_offer(data))
                continue

            dec = session.server_aes.decrypt(data)  # type:ignore
            logger.info(f"[S -> C] {dec.hex(' ').upper()}")

            await peer.send_all(data)

    async def run(self, remote: SocketAddress):
        logger.info(f"[{self.name}] Spawning shard to {remote}...")

        async def accept_tcp_client(stream: trio.SocketStream):
            outward = await trio.open_tcp_stream(*remote)

            sid = next(self._id_generator)
            session = Session(sid, self.key_chain)

            socket_name = stream.socket.getsockname()  # type:ignore
            logger.info(f"[{self.name}] Client {sid} ({socket_name}) connected")

            try:
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(self._client_task, session, stream, outward)
                    nursery.start_soon(self._server_task, session, outward, stream)

            except* trio.BrokenResourceError:
                # We were pranked by a client disconnecting unexpectedly.
                # In that case, we shall just ignore it without bringing
                # the whole shard down.
                pass

            except* ValueError as eg:
                # We received invalid data and can't continue processing.
                for e in eg.exceptions:
                    logger.error(f"[{self.name}] Client {sid} crashed: {e}")

        await trio.serve_tcp(accept_tcp_client, remote.port)
