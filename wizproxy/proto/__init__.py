from typing import Union

from .bytes import Bytes  # noqa
from .frame import Frame  # noqa
from .handshake import EncryptedMessage, SignedMessage  # noqa


class SocketAddress:
    __slots__ = ("ip", "port")

    def __init__(self, ip: Union[bytes, str], port: int):
        if isinstance(ip, str):
            ip = ip.encode()

        self.ip = ip
        self.port = port

    def __str__(self):
        return f"{self.ip.decode()}:{self.port}"

    def __repr__(self):
        return f"{self.__class__.__name__}({self.ip}, {self.port})"
