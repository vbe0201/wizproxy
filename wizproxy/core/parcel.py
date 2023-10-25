from typing import Generic, TypeVar

import trio

Request = TypeVar("Request")
Response = TypeVar("Response")


class Parcel(Generic[Request, Response]):
    """
    A parcel for request/response communication between a shard and
    the proxy instance.
    """

    def __init__(self, data: Request):
        self.data = data
        self._tx, self._rx = trio.open_memory_channel(1)

    async def wait(self) -> Response:
        return await self._rx.receive()

    def answer(self, response: Response):
        self._tx.send_nowait(response)
