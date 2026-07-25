from dataclasses import dataclass

from django.db import models


class Account(models.Model):
    email = models.EmailField()


@dataclass(frozen=True)
class RequestUser:
    is_authenticated: bool
    account: Account


@dataclass(frozen=True)
class Request:
    user: RequestUser
    json: dict[str, str]
