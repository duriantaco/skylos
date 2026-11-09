import asyncio
from typing import Protocol


class Repo(Protocol):
    table_name: str

    def read(self, key: str) -> str: ...


class Store:
    stale_store_name = "x"


class Transport(asyncio.Protocol):
    stale_transport_limit = 3

    def connection_made(self, transport): ...


def load(repo: Repo, key: str) -> str:
    return repo.read(key)


LOAD = load
