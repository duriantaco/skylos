from .base import Action


class Channel:
    pass


class VideoChannel(Channel):
    @property
    def actions(self):
        return (
            Action("read", (("cli", "_cli_read"), ("api", "_api_read"))),
            Action("hot", (("cli", "_cli_hot"),)),
        )

    def _cli_read(self, *, target):
        return [target]

    def _api_read(self, *, target):
        return [target, "api"]

    def _cli_hot(self, *, target):
        return [target, "hot"]

    def _legacy_read(self, *, target):
        return [target, "legacy"]
