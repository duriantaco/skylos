from typing import Protocol


class Runner(Protocol):
    def run(self) -> None: ...


class Service:
    def run(self) -> None:
        return None


class ExtraService:
    def stop(self):
        return None


ExtraService()
