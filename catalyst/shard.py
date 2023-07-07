import itertools
from collections import namedtuple
from functools import partial
from typing import Generic, TypeVar

import trio
from loguru import logger

from .key_chain import KeyChain
from .messages import MSG_CHARACTERSELECTED, MSG_SERVERTRANSFER
from .proto import Bytes, Frame
from .session import Session
from .stream import SessionStream

Request = TypeVar("Request")
Response = TypeVar("Response")

SocketAddress = namedtuple("SocketAddress", ("ip", "port"))

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

    :param name: The human-readable name of the shard.
    :param key_chain: The :class:`KeyChain` for asymmetric crypto.
    :param proxy_tx: The channel for sending commands to the supervisor.
    """

    def __init__(
        self,
        name: str,
        key_chain: KeyChain,
        proxy_tx: trio.abc.SendChannel[Parcel[SocketAddress, SocketAddress]],
    ):
        self.name = name
        self.key_chain = key_chain
        self.proxy_tx = proxy_tx

        self.addr = _DUMMY_ADDR

        self._id_generator = itertools.count()

    async def _client_task(
        self,
        session: Session,
        stream: trio.SocketStream,
        peer: trio.SocketStream,
    ):
        async for res in SessionStream(stream, session, True):
            encrypted, frame = res

            bytes = Bytes(frame)
            frame = Frame.read(bytes)

            if frame.opcode == 5:
                frame.payload = session.session_accept(frame.payload)

            frame.write(bytes)
            frame = bytes.getvalue()

            logger.info(f"[C -> S] {frame.hex(' ').upper()}")

            if encrypted:
                frame = session.client_aes.encrypt(frame)  # type:ignore

            await peer.send_all(frame)

    async def _server_task(
        self,
        session: Session,
        stream: trio.SocketStream,
        peer: trio.SocketStream,
    ):
        async for res in SessionStream(stream, session, False):
            encrypted, frame = res

            bytes = Bytes(frame)
            frame = Frame.read(bytes)

            if frame.opcode == 0:
                frame.payload = session.session_offer(frame.payload)

            elif frame.service_id == 7 and frame.order == 3:
                # When the Login Server admits a new client into the game, it tells
                # it which server to connect to. Spawn a new proxy shard and
                # instruct the client to connect to that instead.
                msg = MSG_CHARACTERSELECTED.decode(frame.payload)

                # Instruct the proxy to spawn the server and await the
                # local socket address of the newly spawned shard.
                parcel = Parcel(SocketAddress(msg["IP"], msg["TCPPort"]))
                await self.proxy_tx.send(parcel)
                shard = await parcel.wait()

                # Fix up the client packet to make it connect to shard.
                msg["IP"] = shard.ip.encode()
                msg["TCPPort"] = shard.port
                frame.payload = MSG_CHARACTERSELECTED.encode(msg)

            elif frame.service_id == 5 and frame.order == 221:
                # On zone changes, a client may be transferred to a different server.
                # We need to make it connect to the proxy again, with fallback being
                # what the client is currently connected to.
                msg = MSG_SERVERTRANSFER.decode(frame.payload)

                # Instruct the proxy to spawn the server and await the
                # local socket address of the newly spawned shard.
                parcel = Parcel(SocketAddress(msg["IP"], msg["TCPPort"]))
                await self.proxy_tx.send(parcel)
                shard = await parcel.wait()

                # Fix up the client packet to make it connect to shard.
                # Use this shard's socket as a fallback.
                msg["IP"] = shard.ip.encode()
                msg["TCPPort"] = shard.port
                msg["FallbackIP"] = self.addr.ip.encode()
                msg["FallbackTCPPort"] = self.addr.port
                frame.payload = MSG_SERVERTRANSFER.encode(msg)

            frame.write(bytes)
            frame = bytes.getvalue()

            logger.info(f"[S -> C] {frame.hex(' ').upper()}")

            if encrypted:
                frame = session.server_aes.encrypt(frame)  # type:ignore

            await peer.send_all(frame)

    async def run(self, nursery: trio.Nursery, remote: SocketAddress) -> SocketAddress:
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

        # Port 0 makes the OS pick for us. So we need to remember the real socket
        # address after the server has started.
        serve_tcp = partial(trio.serve_tcp, handler_nursery=nursery)
        listeners = await nursery.start(serve_tcp, accept_tcp_client, 0)
        self.addr = SocketAddress(*listeners[0].socket.getsockname())  # type:ignore

        return self.addr
