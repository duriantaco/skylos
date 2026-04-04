import attrs


@attrs.define
class User:
    id: int
    name: str
