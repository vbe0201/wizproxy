import trio
from wizmsg.network import Processor

from .key_chain import KeyChain
from .middleman import MiddleMan, SocketAddress


class Proxy:
    def __init__(self, key_chain: KeyChain, processor: Processor, nursery: trio.Nursery):
        self.key_chain = key_chain
        self.processor = processor
        self.servers = {}

        self.nursery = nursery

    def spawn_middleman(self, name: str, addr: SocketAddress):
        middleman = MiddleMan(name, self.key_chain, self.processor)

        self.servers[name] = middleman
        self.nursery.start_soon(middleman.run, addr)
