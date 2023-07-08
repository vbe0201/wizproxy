from pathlib import Path

import trio
from scapy.layers.inet import Ether, IP, TCP
from scapy.utils import PcapNgWriter

from ..proto import Bytes, Frame
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

    async def write_to_file(self, ctx: Context, tcp: TCP, ip: IP, raw: bytes):
        shard = ctx.shard()

        packet = Ether() / ip / tcp / raw
        packet.comment = f"Shard {shard.ip}:{shard.port}, client {ctx.session.sid}"

        await trio.to_thread.run_sync(self.writer.write, packet)

    @listen(Direction.CLIENT_TO_SERVER)
    async def clientbound(self, ctx: Context, frame: Frame):
        bytes = Bytes()
        frame.write(bytes)

        ip = IP(src=ctx.session.client.ip, dst=ctx.session.server.ip)
        tcp = TCP(sport=ctx.session.client.port, dport=ctx.session.server.port)
        await self.write_to_file(ctx, tcp, ip, bytes.getvalue())

    @listen(Direction.SERVER_TO_CLIENT)
    async def serverbound(self, ctx: Context, frame: Frame):
        bytes = Bytes()
        frame.write(bytes)

        ip = IP(src=ctx.session.server.ip, dst=ctx.session.client.ip)
        tcp = TCP(sport=ctx.session.server.port, dport=ctx.session.client.port)
        await self.write_to_file(ctx, tcp, ip, bytes.getvalue())
