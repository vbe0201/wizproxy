import argparse
import json
from pathlib import Path

import trio
from loguru import logger

from .key_chain import KeyChain
from .plugin import ScapyPlugin, VerboseLog
from .proto import SocketAddress
from .proxy import Proxy


async def main(args):
    key_chain = KeyChain(
        json.loads((args.keys / "ki_keys.json").read_text()),
        json.loads((args.keys / "injected_keys.json").read_text()),
    )

    async with trio.open_nursery() as nursery:
        proxy = Proxy(args.host, key_chain, nursery)

        # If requested, enable the scapy plugin.
        if args.capture:
            scapy = ScapyPlugin.from_file(args.capture)

            logger.info(f"Capturing packets to {args.capture.resolve()}")
            proxy.add_plugin(scapy)
        else:
            scapy = None

        # If requested, enable verbose packet logging.
        if args.verbose:
            proxy.add_plugin(VerboseLog())

        await proxy.spawn_shard(SocketAddress(args.login, args.port))

        try:
            await proxy.run()
        finally:
            if scapy is not None:
                scapy.writer.close()


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "keys", type=Path, help="The directory with the two key JSON files"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="The host interface to bind shard sockets to",
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
    parser.add_argument(
        "-c",
        "--capture",
        type=Path,
        help="Path to the pcapng file to write captures to",
    )
    parser.add_argument(
        "-v", "--verbose", help="Enables verbose logging", action="store_true"
    )

    trio.run(main, parser.parse_args())


if __name__ == "__main__":
    run()
