import itertools
from functools import partial
from typing import Generic, TypeVar

import trio
from loguru import logger

from .key_chain import KeyChain
from .plugin import Context, Direction, PluginCollection
from .proto import Bytes, Frame, SocketAddress
from .session import Session
from .stream import SessionStream

Request = TypeVar("Request")
Response = TypeVar("Response")

_DUMMY_ADDR = SocketAddress("0.0.0.0", 0)


class Parcel(Generic[Request, Response]):
    """
    A parcel for request-response communication between a
    :class:`Shard` and the proxy.
    """

    def __init__(self, data: Request):
        self.data = data

        tx, rx = trio.open_memory_channel(1)
        self.sender = tx
        self.receiver = rx

    async def wait(self) -> Response:
        return await self.receiver.receive()

    def answer(self, response: Response):
        self.sender.send_nowait(response)


class Shard:
    """
    Representation of an individual server in the proxy.

    Each shard is bound to one specific game server and all clients
    that would normally connect to that server will connect to the
    shard instead.

    Shards are modeled as an actor system where the proxy supervises
    each shard. Shard actors talk to the proxy to spawn more siblings,
    as required during the processing of network packets.

    :param plugins: The globally registered proxy plugins.
    :param key_chain: The :class:`KeyChain` for asymmetric crypto.
    :param proxy_tx: The channel for sending commands to the supervisor.
    """

    def __init__(
        self,
        plugins: PluginCollection,
        key_chain: KeyChain,
        proxy_tx: trio.abc.SendChannel[Parcel[SocketAddress, SocketAddress]],
    ):
        self.plugins = plugins
        self.key_chain = key_chain
        self.proxy_tx = proxy_tx

        self.addr = _DUMMY_ADDR

        self._id_generator = itertools.count()

    def socket(self) -> str:
        return f"{self.addr.ip}:{self.addr.port}"

    async def _client_task(
        self,
        ctx: Context,
        stream: trio.SocketStream,
        peer: trio.SocketStream,
    ):
        async for res in SessionStream(stream, ctx.session, True):
            encrypted, frame = res

            bytes = Bytes(frame)
            frame = Frame.read(bytes)

            await self.plugins.dispatch(Direction.CLIENT_TO_SERVER, ctx, frame)

            frame.write(bytes)
            frame = bytes.getvalue()

            if encrypted:
                frame = ctx.session.client_aes.encrypt(frame)  # type:ignore

            await peer.send_all(frame)

    async def _server_task(
        self,
        ctx: Context,
        stream: trio.SocketStream,
        peer: trio.SocketStream,
    ):
        async for res in SessionStream(stream, ctx.session, False):
            encrypted, frame = res

            bytes = Bytes(frame)
            frame = Frame.read(bytes)

            await self.plugins.dispatch(Direction.SERVER_TO_CLIENT, ctx, frame)

            frame.write(bytes)
            frame = bytes.getvalue()

            if encrypted:
                frame = ctx.session.server_aes.encrypt(frame)  # type:ignore

            await peer.send_all(frame)

    async def run(self, nursery: trio.Nursery, remote: SocketAddress) -> SocketAddress:
        async def accept_tcp_client(stream: trio.SocketStream):
            outward = await trio.open_tcp_stream(*remote)

            client = SocketAddress(*stream.socket.getsockname())  # type:ignore
            sid = next(self._id_generator)
            session = Session(client, remote, sid, self.key_chain)

            context = Context(self, session)

            logger.info(
                f"[{self.socket()}] Client {sid} ({client.ip}:{client.port}) connected"
            )

            try:
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(self._client_task, context, stream, outward)
                    nursery.start_soon(self._server_task, context, outward, stream)

            except* trio.BrokenResourceError:
                # We were pranked by a client disconnecting unexpectedly.
                # In that case, we shall just ignore it without bringing
                # the whole shard down.
                pass

            except* ValueError as eg:
                # We received invalid data and can't continue processing.
                for e in eg.exceptions:
                    logger.error(f"[{self.socket()}] Client {sid} crashed: {e}")

        # Port 0 makes the OS pick for us. So we need to remember the real socket
        # address after the server has started.
        serve_tcp = partial(trio.serve_tcp, handler_nursery=nursery)
        listeners = await nursery.start(serve_tcp, accept_tcp_client, 0)
        self.addr = SocketAddress(*listeners[0].socket.getsockname())  # type:ignore

        logger.info(f"[{self.socket()}] Spawning shard to {remote}...")

        return self.addr
