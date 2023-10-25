import logging
from datetime import datetime
from pathlib import Path

import trio
from scapy.layers.inet import IP, TCP, Ether
from scapy.utils import PcapNgWriter

from wizproxy.proto import Frame, SocketAddress

from . import Context, Direction, Plugin, listen

# Silence overly verbose scapy logging except for errors.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class ScapyPlugin(Plugin):
    """
    A plugin which writes frame data to pcapng files.

    Each packet is written as TCP, pretending to be directly exchanged
    between a local client and the remote server.

    Each frame has a machine-parseable comment attached, describing
    the local shard that produced the frame and what client it was.
    """

    def __init__(self, writer: PcapNgWriter):
        super().__init__()

        self.writer = writer

    @classmethod
    def from_file(cls, path: Path):
        if path.is_dir():
            now = datetime.now()
            path = path / now.strftime("wizproxy_%Y-%m-%d_%H-%M-%S.pcapng")

        writer = PcapNgWriter(str(path.resolve()))
        return cls(writer)

    async def write_to_file(
        self, ctx: Context, src: SocketAddress, dest: SocketAddress, raw: bytes
    ):
        shard = ctx.shard_addr

        packet = (
            Ether()
            / IP(src=src.ip, dst=dest.ip)
            / TCP(sport=src.port, dport=dest.port)
            / raw
        )
        packet.comment = "\n".join(
            (
                f"Shard {shard}",
                f"Client {ctx.session.sid}",
            )
        )

        await trio.to_thread.run_sync(self.writer.write, packet)

    @listen(Direction.CLIENT_TO_SERVER, dirty=False)
    async def clientbound(self, ctx: Context, frame: Frame):
        session = ctx.session
        await self.write_to_file(ctx, session.client, session.server, frame.original)

    @listen(Direction.SERVER_TO_CLIENT, dirty=False)
    async def serverbound(self, ctx: Context, frame: Frame):
        session = ctx.session
        await self.write_to_file(ctx, session.server, session.client, frame.original)
