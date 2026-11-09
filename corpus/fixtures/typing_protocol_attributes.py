from typing import Protocol


class Repo(Protocol):
    table_name: str

    def read(self, key: str) -> str: ...


class Store:
    stale_store_name = "x"


def load(repo: Repo, key: str) -> str:
    return repo.read(key)


LOAD = load
