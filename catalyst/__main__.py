import json
from pathlib import Path

import trio

from .key_chain import KeyChain
from .proxy import Proxy
from .shard import SocketAddress

ROOT = Path(__file__).parent.parent
GAME_DATA = ROOT / "game_data"

DE_LOGIN_ADDR = SocketAddress("login-de.eu.wizard101.com", 12000)
US_LOGIN_ADDR = SocketAddress("login.us.wizard101.com", 12000)


async def main():
    key_chain = KeyChain(
        json.loads((GAME_DATA / "ki_keys.json").read_text()),
        json.loads((GAME_DATA / "injected_keys.json").read_text()),
    )

    async with trio.open_nursery() as nursery:
        proxy = Proxy(key_chain, nursery)
        proxy.spawn_shard("Login", DE_LOGIN_ADDR)
        await proxy.run()


def run():
    trio.run(main)


if __name__ == "__main__":
    run()
