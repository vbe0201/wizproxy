from typing import Optional

import trio

from .key_chain import KeyChain
from .plugin import Plugin, PluginCollection, builtin
from .shard import Shard, SocketAddress


class Proxy:
    """
    Representation of the proxy instance.

    A proxy governs many shards, each being representative of a
    tunnel to a chosen game server. Many clients can connect to
    each shard and can spawn more shard siblings on demand.

    Communication between :class:`Shard`s and the :class:`Proxy`
    is realized via message passing; no inner state is shared
    and synchronization is not required.

    :param host: The host interface to bind shards to.
    :param key_chain: The key chain to use for cryptographic operations.
    :param nursery: The nursery to spawn shards on.
    """

    def __init__(self, host: Optional[str], key_chain: KeyChain, nursery: trio.Nursery):
        self.host = host
        self.key_chain = key_chain
        self.nursery = nursery

        self.plugins = PluginCollection()
        self.plugins.add(builtin.Builtin())

        self._shards = {}

        tx, rx = trio.open_memory_channel(32)
        self.sender = tx
        self.receiver = rx

    def add_plugin(self, plugin: Plugin):
        self.plugins.add(plugin)

    async def spawn_shard(self, addr: SocketAddress) -> SocketAddress:
        # If the shard is already running, ignore it.
        if local := self._shards.get(addr):
            return local

        shard = Shard(self.plugins, self.key_chain, self.sender.clone())

        self._shards[addr] = await shard.run(self.host, self.nursery, addr)
        return shard.addr

    async def run(self):
        while True:
            parcel = await self.receiver.receive()

            addr = await self.spawn_shard(parcel.data)
            parcel.answer(addr)
