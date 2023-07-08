from typing import Callable, Optional

import trio

from ..proto import Frame
from ..session import Session
from .filter import Direction, _make_filter


def listen(
    dir: Direction,
    *,
    opcode: Optional[int] = None,
    service_id: Optional[int] = None,
    order: Optional[int] = None
):
    """
    Defines a new packet listener inside a proxy plugin.

    Listeners are coroutines accepting `self, session, frame` as
    its arguments.

    They do not return anything and can be used to manipulate and
    introspect the frame data.
    """

    def decorator(func):
        func.__proxy_filter__ = _make_filter(dir, opcode, service_id, order)
        func.__proxy_listener__ = True
        return func

    return decorator


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

    Plugins are built as subclasses of this class, with packet listeners
    defined using the :func:`listen` decorator.

    They are passed the session of the calling client and a reference to
    its frame data, allowing for introspection and manipulation.

    Listener dispatch is task-safe by default, plugin writers do not have
    to employ synchronization when trying to access class state.
    """

    def __init__(self):
        self._lock = trio.Lock()

    async def _dispatch(self, dir: Direction, session: Session, frame: Frame):
        for listener in self.__proxy_listeners__:  # type:ignore
            filter = getattr(listener, "__proxy_filter__")
            if dir == filter.direction and filter.can_dispatch(frame):
                async with self._lock:
                    await listener(self, session, frame)


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

    async def dispatch(self, dir: Direction, session: Session, frame: Frame):
        for plugin in self.plugins:
            await plugin._dispatch(dir, session, frame)
