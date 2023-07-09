import logging
from pathlib import Path

# Silence overly verbose scapy logging except for errors.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import trio
from scapy.layers.inet import IP, TCP, Ether
from scapy.utils import PcapNgWriter

from ..proto import Bytes, Frame, SocketAddress
from . import Context, Direction, Plugin, listen


class ScapyPlugin(Plugin):
    """
    A plugin which writes frame data to pcapng files.

    Each packet is written as TCP, pretending to be directly
    exchanged between a local client and the remote server.

    Each packet has a comment attached, describing the local
    shard that produced it and what client it was.
    """

    def __init__(self, writer: PcapNgWriter):
        super().__init__()

        self.writer = writer

    @classmethod
    def from_file(cls, path: Path):
        writer = PcapNgWriter(str(path.resolve()))
        return cls(writer)

    async def write_to_file(
        self, ctx: Context, source: SocketAddress, dest: SocketAddress, raw: bytes
    ):
        shard = ctx.shard()

        packet = (
            Ether()
            / IP(src=source.ip, dst=dest.ip)
            / TCP(sport=source.port, dport=dest.port)
            / raw
        )
        packet.comment = f"Shard {shard.ip}:{shard.port}, client {ctx.session.sid}"

        await trio.to_thread.run_sync(self.writer.write, packet)

    @listen(Direction.CLIENT_TO_SERVER)
    async def clientbound(self, ctx: Context, frame: Frame):
        bytes = Bytes()
        frame.write(bytes)

        session = ctx.session
        await self.write_to_file(ctx, session.client, session.server, bytes.getvalue())

    @listen(Direction.SERVER_TO_CLIENT)
    async def serverbound(self, ctx: Context, frame: Frame):
        bytes = Bytes()
        frame.write(bytes)

        session = ctx.session
        await self.write_to_file(ctx, session.server, session.client, bytes.getvalue())
