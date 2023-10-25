from enum import Enum, auto
from typing import Optional

from wizproxy.proto import Frame


class Direction(Enum):
    """The direction in which a frame is travelling."""

    SERVER_TO_CLIENT = auto()
    CLIENT_TO_SERVER = auto()


class Filter:
    def __init__(
        self,
        direction: Direction,
        opcode: Optional[int],
        service_id: Optional[int],
        order: Optional[int],
    ):
        if opcode is not None and service_id is not None:
            raise ValueError("unsupported filter for control and data frames")

        if order is not None and service_id is None:
            raise ValueError("cannot filter by order without service")

        self.direction = direction
        self.opcode = opcode
        self.service_id = service_id
        self.order = order

    def can_dispatch(self, frame: Frame) -> bool:
        if self.opcode is not None:
            return frame.opcode == self.opcode

        elif self.service_id is not None:
            if self.order is None:
                return frame.service_id == self.service_id

            return frame.service_id == self.service_id and frame.order == self.order

        return True
