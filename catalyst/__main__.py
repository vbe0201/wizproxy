import argparse
import json
from pathlib import Path

import trio
from loguru import logger

from .key_chain import KeyChain
from .proxy import Proxy
from .shard import SocketAddress


async def main(args):
    key_chain = KeyChain(
        json.loads((args.keys / "ki_keys.json").read_text()),
        json.loads((args.keys / "injected_keys.json").read_text()),
    )

    async with trio.open_nursery() as nursery:
        proxy = Proxy(key_chain, nursery)

        addr = await proxy.spawn_shard(SocketAddress(args.login, args.port))
        logger.info(f"Proxy listening on {addr.ip}:{addr.port}")

        await proxy.run()


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "keys", type=Path, help="The directory with the two key JSON files"
    )
    parser.add_argument(
        "-l",
        "--login",
        type=str,
        default="login.us.wizard101.com",
        help="The Login Server IP to proxy",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=12000,
        help="The TCP port to spawn the Login Server on",
    )

    trio.run(main, parser.parse_args())


if __name__ == "__main__":
    run()
