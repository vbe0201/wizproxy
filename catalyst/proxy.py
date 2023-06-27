import trio

from .key_chain import KeyChain
from .shard import Shard, SocketAddress


class Proxy:
    """
    Representation of the proxy instance.

    A proxy governs many shards, each being representative of a
    tunnel to a chosen game server. Many clients can connect to
    each shard and can spawn more shard siblings on demand.

    Communication between :class:`Shard`s and the :class:`Proxy`
    is implemented via message passing; no inner state is shared
    and synchronization is not required.
    """

    def __init__(self, key_chain: KeyChain, nursery: trio.Nursery):
        self.key_chain = key_chain
        self.nursery = nursery

        self.shards = {}

        tx, rx = trio.open_memory_channel(32)
        self.sender = tx
        self.receiver = rx

    def spawn_shard(self, name: str, addr: SocketAddress):
        # If the shard is already running, ignore it.
        if name in self.shards:
            return

        tx, rx = trio.open_memory_channel(4)
        shard = Shard(name, self.key_chain, self.sender, rx)

        self.shards[name] = tx
        self.nursery.start_soon(shard.run, addr)

    async def run(self):
        while True:
            name, addr = await self.receiver.receive()
            self.spawn_shard(name, addr)
