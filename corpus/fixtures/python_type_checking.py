from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pkg import User


def takes_user(user: "User"):
    return user
