import itertools
from collections import namedtuple

import trio
from loguru import logger
from wizmsg.network import Processor, controls, MessageData

from .buffer import PacketBuffer, is_large_frame
from .key_chain import KeyChain
from .session import Session

SocketAddress = namedtuple("SocketAddress", ("ip", "port"))


class MiddleMan:
    def __init__(
        self,
        name: str,
        key_chain: KeyChain,
        processor: Processor,
        tx: trio.MemorySendChannel,
    ):
        self.name = name
        self.key_chain = key_chain
        self.processor = processor

        self.spawn_tx = tx

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

                processed = self.processor.process_frame(frame)
                logger.info(f"[C -> S] {processed=}")

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

                processed = self.processor.process_frame(frame)
                logger.info(f"[S -> C] {processed=}")

                if isinstance(processed, controls.SessionOffer):
                    # For Session Offer, we need to re-sign it so the client accepts it.
                    # Otherwise, re-encrypt any frame passing through if necessary.
                    frame = session.session_offer(processed, frame)

                elif (
                    isinstance(processed, MessageData)
                    and processed.service_id == 7
                    and processed.order_id == 3
                ):
                    # When the Login Server admits a new client into the game, it tells
                    # it which socket to connect to. Spawn a new proxy server for that.
                    ip = processed.parameters["IP"]
                    port = processed.parameters["TCPPort"]

                    processed.parameters["IP"] = "192.168.178.22"

                    frame = self.processor.prepare_frame(processed)
                    await self.spawn_tx.send(
                        (f"ZoneServer-{port}", SocketAddress(ip, port))
                    )

                elif isinstance(processed, MessageData) and processed.service_id == 5 and processed.name == "MSG_SERVERTRANSFER":
                    # TODO: Fill in order value once we have it.
                    logger.warning(f"Add order for servertransfer: {processed.order_id}")

                    # When game requests a server transfer, it probes the client if
                    # connecting to the given server would be possible.
                    ip = processed.parameters["IP"]
                    port = processed.parameters["TCPPort"]

                    processed.parameters["IP"] = processed.parameters["FallbackIP"] = "192.168.178.22"
                    processed.parameters["FallbackTCPPort"] = processed.parameters["TCPPort"]

                    frame = self.processor.prepare_frame(processed)
                    await self.spawn_tx.send(
                        (f"ZoneTransfer-{port}", SocketAddress(ip, port))
                    )

                if encrypted:
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
