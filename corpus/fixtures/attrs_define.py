import attrs


@attrs.define
class User:
    id: int
    name: str


class UserRecord:
    account_id: int = 0
    display_name: str = ""
