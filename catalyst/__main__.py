from pathlib import Path

import trio

from .key_chain import KeyChain
from .middleman import SocketAddress
from .proxy import Proxy

ROOT = Path(__file__).parent.parent
GAME_DATA = ROOT / "game_data"

US_LOGIN_ADDR = SocketAddress("login.us.wizard101.com", 12000)


async def main():
    key_chain = KeyChain(GAME_DATA / "ki_keys.json", GAME_DATA / "injected_keys.json")

    async with trio.open_nursery() as nursery:
        proxy = Proxy(key_chain, nursery)
        proxy.spawn_middleman("Login", US_LOGIN_ADDR)


def run():
    trio.run(main)


if __name__ == "__main__":
    run()
