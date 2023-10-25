import itertools
from functools import partial
from typing import Optional

import trio
from loguru import logger

from wizproxy.crypto import KeyChain
from wizproxy.plugin import Context, Direction, PluginCollection
from wizproxy.proto import Bytes, Frame, SocketAddress
from wizproxy.session import ClientSig, Session
from wizproxy.transport import FrameStream

from .parcel import Parcel

_DUMMY_ADDR = SocketAddress("0.0.0.0", 0)


class Shard:
    """
    Representation of an individual server in the proxy.

    Each shard is bound to one specific game server and all clients
    that would normally connect to that server will connect to the
    shard instead.

    Shards are modeled as an actor system where the proxy supervises
    each shard. Shard actors talk to the proxy to spawn siblings in
    response to a connected client trying to switch servers.

    :param plugins: The globally registered proxy plugins.
    :param key_chain: The :class:`KeyChain` for asymmetric crypto.
    :param client_sig: Optionally, a decrypted ClientSig if present.
    :param proxy_tx: The channel for sending commands to the supervisor.
    """

    def __init__(
        self,
        plugins: PluginCollection,
        key_chain: KeyChain,
        client_sig: Optional[ClientSig],
        proxy_tx: trio.abc.SendChannel[Parcel[SocketAddress, SocketAddress]],
    ):
        self.plugins = plugins
        self.key_chain = key_chain
        self.client_sig = client_sig
        self.proxy_tx = proxy_tx

        self.self_addr = _DUMMY_ADDR
        self.remote_addr = _DUMMY_ADDR

        self._id_generator = itertools.count()

    def __str__(self) -> str:
        return str(self.self_addr)

    async def tunnel(
        self,
        direction: Direction,
        ctx: Context,
        stream: trio.SocketStream,
        peer: trio.SocketStream,
    ):
        is_client = direction == Direction.CLIENT_TO_SERVER
        session = ctx.session
        buf = Bytes()

        async for res in FrameStream(stream, session, is_client):
            encrypted, frame = res

            # Deserialize the next received frame.
            buf.load_frame(frame)
            frame = Frame.read(buf)

            # Run all plugins on the frame and decide if it should be omitted.
            if not await self.plugins.dispatch(direction, ctx, frame):
                continue

            # if the frame is marked dirty, re-serialize it.
            # Otherwise, just reuse the original data we backed up.
            if frame.dirty:
                frame.write(buf)
                raw = buf.getvalue()
            else:
                raw = frame.original

            # Encrypt the frame data, if necessary.
            if encrypted:
                if is_client:
                    raw = session.client_aes.encrypt(raw)
                else:
                    raw = session.server_aes.encrypt(raw)

            await peer.send_all(raw)

        buf.close()

    async def _client_task(
        self,
        ctx: Context,
        stream: trio.SocketStream,
        peer: trio.SocketStream,
    ):
        await self.tunnel(Direction.CLIENT_TO_SERVER, ctx, stream, peer)

    async def _server_task(
        self,
        ctx: Context,
        stream: trio.SocketStream,
        peer: trio.SocketStream,
    ):
        await self.tunnel(Direction.SERVER_TO_CLIENT, ctx, stream, peer)

    async def run(
        self,
        host: Optional[str],
        nursery: trio.Nursery,
        remote: SocketAddress,
    ) -> SocketAddress:
        async def accept_tcp_client(stream: trio.SocketStream):
            outward = await trio.open_tcp_stream(remote.ip, remote.port)
            client_sock = stream.socket.getsockname()

            client = SocketAddress(client_sock[0], client_sock[1])
            sid = next(self._id_generator)
            session = Session(client, remote, sid, self.key_chain, self.client_sig)
            context = Context(self, session)

            logger.info(f"[{self}] Client {sid} ({client}) connected")

            try:
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(self._client_task, context, stream, outward)
                    nursery.start_soon(self._server_task, context, outward, stream)

            except* trio.BrokenResourceError:
                # We were pranked by a client disconnecting unexpectedly.
                # In that case, we shall just ignore it without bringing
                # the whole shard down.
                pass

            except* trio.TooSlowError:
                logger.info(f"[{self}] Client {sid} disconnected due to inactivity")

            except* ValueError as eg:
                # We received invalid data and can't continue processing.
                for e in eg.exceptions:
                    logger.error(f"[{self}] Client {sid} crashed: {e}")

        # Port 0 makes the OS pick for us. So we need to remember the
        # assigned address after the server has started.
        serve_tcp = partial(trio.serve_tcp, host=host, handler_nursery=nursery)
        listeners = await nursery.start(serve_tcp, accept_tcp_client, 0)

        server_sock = listeners[0].socket.getsockname()
        self.self_addr = SocketAddress(server_sock[0], server_sock[1])
        self.remote_addr = remote

        logger.info(f"[{self}] Spawning shard to {remote}..")

        return self.self_addr
