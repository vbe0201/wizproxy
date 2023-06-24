import trio

from .middleman import MiddleMan, SocketAddress


class Proxy:
    def __init__(self, nursery: trio.Nursery):
        self.servers = {}

        self.nursery = nursery

    def spawn_middleman(self, name: str, addr: SocketAddress):
        middleman = MiddleMan(name)

        self.servers[name] = middleman
        self.nursery.start_soon(middleman.run, addr)
