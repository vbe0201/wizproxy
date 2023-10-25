from typing import Callable, Optional

import trio

from wizproxy.core.parcel import Parcel
from wizproxy.proto import Frame, SocketAddress
from wizproxy.session import Session

from ._filter import Direction, Filter


def listen(
    dir: Direction,
    *,
    opcode: Optional[int] = None,
    service_id: Optional[int] = None,
    order: Optional[int] = None,
    dirty: bool = True,
):
    """
    Defines a new packet listener inside a proxy plugin.

    Listeners are coroutines accepting `self, context, frame` as
    their arguments.

    They may optionally return a bool indicating whether a frame
    should be omitted in the forwarding of the traffic.

    When a frame wanders through a listener, it is marked dirty
    and must be re-serialized to account for eventual changes
    done by the handler.

    Write filters which are conservative in what they accept to
    keep the number of needed re-serializations low.
    """

    def decorator(func):
        func.__proxy_filter__ = Filter(dir, opcode, service_id, order)
        func.__proxy_dirty__ = dirty
        func.__proxy_listener__ = True
        return func

    return decorator


class Context:
    """
    Processing context for a proxy plugin.

    Contexts provide introspection into state and metadata of the
    connection a frame is coming from.
    """

    def __init__(self, shard, session: Session):
        self._shard = shard
        self.session = session

    @property
    def shard_addr(self) -> SocketAddress:
        return self._shard.self_addr

    @property
    def remote_addr(self) -> SocketAddress:
        return self._shard.remote_addr

    async def spawn_shard(self, addr: SocketAddress) -> SocketAddress:
        parcel = Parcel(addr)

        await self._shard.proxy_tx.send(parcel)
        return await parcel.wait()


class PluginMeta(type):
    """
    Metaclass for dynamically gathering listeners in a :class:`Plugin`.

    This respects the inheritance hierarchy of the plugin, so that all
    listeners in a parent plugin class are also listeners in the child.
    """

    __proxy_listeners__: list[Callable]

    def __new__(cls, name, bases, attrs):
        listeners = []

        new_cls = super().__new__(cls, name, bases, attrs)
        for base in reversed(new_cls.__mro__):
            for value in base.__dict__.values():
                if callable(value) and hasattr(value, "__proxy_listener__"):
                    listeners.append(value)

        new_cls.__proxy_listeners__ = listeners
        return new_cls


class Plugin(metaclass=PluginMeta):
    """
    Base class for plugins which extend proxy functionality.

    Plugins are used to introspect and modify the contents of selected
    frames passing through the connection.

    Each plugin is built as a subclasses of this class, with packet
    listeners defined using the :func:`listen` decorator.

    Listener dispatch is task-safe by default, plugin writers do not have
    to employ synchronization when trying to access class state.
    """

    def __init__(self):
        self._lock = trio.Lock()

    async def _dispatch(self, dir: Direction, ctx: Context, frame: Frame) -> bool:
        should_not_skip = True

        for listener in type(self).__proxy_listeners__:
            f = getattr(listener, "__proxy_filter__")
            if dir == f.direction and f.can_dispatch(frame):
                async with self._lock:
                    res = await listener(self, ctx, frame)
                    if res is None:
                        res = True

                    should_not_skip = should_not_skip and res

                frame.dirty = frame.dirty or getattr(listener, "__proxy_dirty__")

        return should_not_skip


class PluginCollection:
    """
    A collection of registered plugins, shared with each shard.

    A call to :meth:`dispatch` will invoke all eligible listeners
    throughout all registered plugins.
    """

    def __init__(self):
        self.plugins = []

    def add(self, plugin: Plugin):
        self.plugins.append(plugin)

    async def dispatch(self, dir: Direction, ctx: Context, frame: Frame) -> bool:
        should_not_skip = True
        for plugin in self.plugins:
            res = await plugin._dispatch(dir, ctx, frame)
            should_not_skip = should_not_skip and res

        return should_not_skip
