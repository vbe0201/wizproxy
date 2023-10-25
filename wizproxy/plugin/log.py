from loguru import logger

from wizproxy.proto import Frame

from . import Direction, Plugin, listen


class VerboseLog(Plugin):
    """Logs packets with their direction to stdout."""

    @listen(Direction.CLIENT_TO_SERVER, dirty=False)
    async def cs(self, _, frame: Frame):
        logger.info(f"[C -> S] {frame.original.hex(' ')}")

    @listen(Direction.SERVER_TO_CLIENT, dirty=False)
    async def sc(self, _, frame: Frame):
        logger.info(f"[S -> C] {frame.original.hex(' ')}")
