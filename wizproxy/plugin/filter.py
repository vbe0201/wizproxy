from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from ..proto import Frame


class Direction(Enum):
    """The direction in which a frame is traveling."""

    #: Listener is only invoked for frames going from server to client.
    SERVER_TO_CLIENT = auto()

    #: Listener is only invoked for frames going from client to server.
    CLIENT_TO_SERVER = auto()


@dataclass
class _Filter:
    direction: Direction

    opcode: Optional[int]
    service_id: Optional[int]
    order: Optional[int]

    def can_dispatch(self, frame: Frame) -> bool:
        if self.opcode is not None:
            return frame.opcode == self.opcode

        elif self.service_id is not None:
            if self.order is None:
                return frame.service_id == self.service_id

            return frame.service_id == self.service_id and frame.order == self.order

        return True


def _make_filter(
    direction: Direction,
    opcode: Optional[int],
    service_id: Optional[int],
    order: Optional[int],
) -> _Filter:
    if opcode is not None and service_id is not None:
        raise ValueError("Unsupported filter for control and data frames")

    if order is not None and service_id is None:
        raise ValueError("Cannot filter by order without service")

    return _Filter(direction, opcode, service_id, order)
