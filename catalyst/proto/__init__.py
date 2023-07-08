from collections import namedtuple

from .bytes import Bytes  # noqa
from .frame import Frame  # noqa
from .handshake import EncryptedMessage, SignedMessage  # noqa

SocketAddress = namedtuple("SocketAddress", ("ip", "port"))
