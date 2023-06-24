import trio

from .middleman import SocketAddress
from .proxy import Proxy

US_LOGIN_ADDR = SocketAddress("login.us.wizard101.com", 12000)


async def main():
    async with trio.open_nursery() as nursery:
        proxy = Proxy(nursery)
        proxy.spawn_middleman("Login", US_LOGIN_ADDR)


def run():
    trio.run(main)


if __name__ == "__main__":
    run()
