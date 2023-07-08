from loguru import logger

from ..proto import Frame
from . import Direction, Plugin, listen


class VerboseLog(Plugin):
    """
    Logs packets with their direction to stdout.
    """

    @listen(Direction.CLIENT_TO_SERVER)
    async def cs(self, _, frame: Frame):
        logger.info(f"[C -> S] {frame}")

    @listen(Direction.SERVER_TO_CLIENT)
    async def sc(self, _, frame: Frame):
        logger.info(f"[S -> C] {frame}")
