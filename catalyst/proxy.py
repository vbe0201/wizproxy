import trio
from wizmsg.network import Processor

from .key_chain import KeyChain
from .middleman import MiddleMan, SocketAddress


class Proxy:
    def __init__(
        self, key_chain: KeyChain, processor: Processor, nursery: trio.Nursery
    ):
        self.key_chain = key_chain
        self.processor = processor
        self.servers = {}

        self.nursery = nursery

        tx, rx = trio.open_memory_channel(32)
        self.sender = tx
        self.receiver = rx

    def spawn_middleman(self, name: str, addr: SocketAddress):
        # If the middleman is already running, don't spawn another one.
        if name in self.servers:
            return

        middleman = MiddleMan(name, self.key_chain, self.processor, self.sender)

        self.servers[name] = middleman
        self.nursery.start_soon(middleman.run, addr)

    async def run(self):
        while True:
            name, addr = await self.receiver.receive()
            self.spawn_middleman(name, addr)
