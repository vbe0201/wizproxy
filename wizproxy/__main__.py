import json
import platform
import socket
from pathlib import Path
from typing import Optional

import click
import trio
from loguru import logger

from .core import Proxy
from .crypto import KeyChain
from .plugin.log import VerboseLogPlugin
from .plugin.scapy import ScapyPlugin
from .proto import SocketAddress
from .session import ClientSig


async def main(
    key_dir: Path,
    host: Optional[str],
    login: SocketAddress,
    capture: Optional[Path],
    verbose: bool,
):
    key_chain = KeyChain(
        json.loads((key_dir / "ki_keys.json").read_text()),
        json.loads((key_dir / "injected_keys.json").read_text()),
    )

    client_sig_path = key_dir / "ClientSig.dec.bin"
    if client_sig_path.exists():
        client_sig = ClientSig(client_sig_path.read_bytes())
    else:
        client_sig = None

    if host is None and platform.system() == "Windows":
        # Windows default wildcard interface behaves funky and
        # "0.0.0.0" causes trouble when the game client attempts
        # to connect to the proxy.
        #
        # This is not an issue under Wine (Linux and macOS), so
        # we want to use the proper local interface as a default
        # on Windows.
        host = socket.gethostbyname(socket.gethostname())

    async with trio.open_nursery() as nursery:
        proxy = Proxy(host, key_chain, client_sig, nursery)

        # If requested, enable the scapy plugin.
        if capture is not None:
            scapy = ScapyPlugin.from_file(capture)

            logger.info(f"Capturing packets to {capture.resolve()}")
            proxy.add_plugin(scapy)
        else:
            scapy = None

        # If requested, enable verbose packet logging.
        if verbose:
            proxy.add_plugin(VerboseLogPlugin())

        # Spawn the initial shard to proxy the login server.
        await proxy.spawn_shard(login)

        try:
            await proxy.run()
        finally:
            if scapy is not None:
                scapy.writer.close()


@click.command()
@click.argument(
    "key_dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("-h", "--host", help="The host interface to bind sockets to")
@click.option(
    "-l",
    "--login",
    default="login.us.wizard101.com",
    show_default=True,
    help="The Login Server IP",
)
@click.option(
    "-p",
    "--port",
    default=12000,
    show_default=True,
    help="The TCP port of the Login Server",
)
@click.option(
    "-c",
    "--capture",
    type=click.Path(path_type=Path),
    help="Captures packets to a pcapng file.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Enables verbose logging.",
)
def run(key_dir, host, login, port, capture, verbose):
    """Starts the proxy with required files in the key directory.

    The expected files are 'ki_keys.json', a dump of recent client public
    keys and 'injected_keys.json', a controlled key pair for the client
    connecting to the proxy.

    Optionally, if a 'ClientSig.dec.bin' file exists, it will be used to
    make the client communicate with the proxy in plaintext.
    """
    login = SocketAddress(login, port)
    trio.run(main, key_dir, host, login, capture, verbose)


if __name__ == "__main__":
    run()
