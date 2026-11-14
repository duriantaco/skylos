import functools
from abc import ABC, abstractmethod


def _scale(value, factor):
    return value * 2


class Report:
    def _line(self, text, width):
        return text

    def render(self):
        return self._line("x", 80)


def _on_event(event, context):
    return event


def _wrapped(payload, meta):
    return payload


def _variadic(value, *args, **kwargs):
    return value


def public_api(value, reserved):
    return value


def _by_name(value, extra):
    return value


def _default_hook(value, recorder):
    """Leave empty by default."""
    return ""


if hasattr(functools, "cache"):

    def _alternative(value, spare):
        return value

else:

    def _alternative(value, spare):
        return value + spare


class Base(ABC):
    @abstractmethod
    def _step(self, item, options): ...


class Impl(Base):
    def _step(self, item, options):
        return item


class Plain:
    def _hook(self, item, hint):
        return item


class Special(Plain):
    def _hook(self, item, hint):
        return item + hint


def apply(callback):
    return callback("event", "context")


print(
    _scale(1, 2),
    Report().render(),
    apply(_on_event),
    functools.partial(_wrapped, 1)(2),
    _variadic(1, 2, key=3),
    public_api(1, 2),
    globals()["_by_name"](1, 2),
    _default_hook(1, 2),
    _alternative(1, 2),
    Impl()._step(1, 2),
    Plain()._hook(1, 2),
    Special()._hook(1, 2),
)
