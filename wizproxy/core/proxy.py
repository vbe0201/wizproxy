from typing import Optional

import trio

from wizproxy.crypto import KeyChain
from wizproxy.plugin import Plugin, PluginCollection
from wizproxy.plugin.builtin import Builtin
from wizproxy.proto import SocketAddress
from wizproxy.session import ClientSig

from .shard import Shard


class Proxy:
    """
    Representation of the proxy instance.

    A proxy governs many shards, each being representative of a tunnel
    to a chosen game server. Many clients can connect to each shard
    and more shards are spawned on demand.

    Communication between shards and the proxy instance is realized via
    message passing; no inner state is shared and synchronization is not
    required.

    :param host: The host interface to bind shards to.
    :param key_chain: They key chain to use for cryptographic operations.
    :param client_sig: Optionally, a decrypted ClientSig if present.
    :param nursery: The nursery to spawn shards on.
    """

    def __init__(
        self,
        host: Optional[str],
        key_chain: KeyChain,
        client_sig: Optional[ClientSig],
        nursery: trio.Nursery,
    ):
        self.host = host
        self.key_chain = key_chain
        self.client_sig = client_sig
        self.nursery = nursery

        self.plugins = PluginCollection()
        self.plugins.add(Builtin())

        self._shards = {}

        self._tx, self._rx = trio.open_memory_channel(32)

    def add_plugin(self, plugin: Plugin):
        self.plugins.add(plugin)

    async def spawn_shard(self, addr: SocketAddress) -> SocketAddress:
        # If the shard is already running, just return its address.
        if shard := self._shards.get(addr):
            return shard

        shard = Shard(self.plugins, self.key_chain, self.client_sig, self._tx.clone())
        self._shards[addr] = await shard.run(self.host, self.nursery, addr)

        return shard.self_addr

    async def run(self):
        while True:
            parcel = await self._rx.receive()
            addr = await self.spawn_shard(parcel.data)
            parcel.answer(addr)
