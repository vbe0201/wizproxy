import itertools
from collections import namedtuple

import trio
from loguru import logger
from wizmsg.network import Processor, controls

from .buffer import PacketBuffer, is_large_frame
from .key_chain import KeyChain
from .session import Session

SocketAddress = namedtuple("SocketAddress", ("ip", "port"))


class MiddleMan:
    def __init__(self, name: str, key_chain: KeyChain):
        self.name = name
        self.key_chain = key_chain

        self.processor = Processor()

        self.id_generator = itertools.count()

    async def _client_task(
        self, session: Session, stream: trio.SocketStream, peer: trio.SocketStream
    ):
        buffer = PacketBuffer()

        async for packet in stream:
            buffer.add_packet(packet)

            if res := buffer.poll_frame(session.client_aes):
                encrypted, frame = res

                # For Session Accept, we need to re-encrypt it so the server accepts it.
                # Otherwise, re-encrypt any frame passing through if necessary.
                opcode = frame[9 if is_large_frame(frame) else 5]
                if opcode == 5:
                    frame = session.session_accept(frame)

                # FIXME: Add DML protocols.
                try:
                    processed = self.processor.process_frame(frame)
                    logger.info(f"[C -> S] {processed=}")
                except RuntimeError:
                    logger.info(f"[C -> S] {frame.hex(' ').upper()}")

                if encrypted:
                    frame = session.client_aes.encrypt(frame)  # type:ignore

                await peer.send_all(frame)

    async def _server_task(
        self, session: Session, stream: trio.SocketStream, peer: trio.SocketStream
    ):
        buffer = PacketBuffer()

        async for packet in stream:
            buffer.add_packet(packet)

            if res := buffer.poll_frame(session.server_aes):
                encrypted, frame = res

                # FIXME: Add DML protocols.
                try:
                    processed = self.processor.process_frame(frame)
                    logger.info(f"[S -> C] {processed=}")
                except RuntimeError:
                    processed = None
                    logger.info(f"[S -> C] {frame.hex(' ').upper()}")

                # For Session Offer, we need to re-sign it so the client accepts it.
                # Otherwise, re-encrypt any frame passing through if necessary.
                if isinstance(processed, controls.SessionOffer):
                    frame = session.session_offer(processed, frame)
                elif encrypted:
                    frame = session.server_aes.encrypt(frame)  # type:ignore

                await peer.send_all(frame)

    async def run(self, remote: SocketAddress):
        logger.info(f"[{self.name}] Spawning middleman to {remote}...")

        async def accept_tcp_client(stream: trio.SocketStream):
            outward = await trio.open_tcp_stream(*remote)

            sid = next(self.id_generator)
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
                # the whole middleman server down.
                pass

            except* ValueError as eg:
                # We received invalid frame data and can't continue processing.
                for e in eg.exceptions:
                    logger.error(f"[{self.name}] Client {sid} crashed: {e}")

        await trio.serve_tcp(accept_tcp_client, remote.port)
