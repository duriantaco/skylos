from typing import TYPE_CHECKING, List, Optional, TypedDict, TypeVar, Union, cast

if TYPE_CHECKING:
    from _typeshed import DataclassInstance
    from decimal import Decimal
    from fractions import Fraction
    from uuid import UUID

T = TypeVar("T", bound="DataclassInstance")

ItemData = Union["StandardData", "RadioData"]


class Item(TypedDict):
    data: "ItemData"
    extra: Optional["ExtraData"]
    history: List["HistoryData"]


class StandardData(TypedDict):
    name: str


class RadioData(TypedDict):
    options: list


class ExtraData(TypedDict):
    note: str


class HistoryData(TypedDict):
    stamp: int


class CastTarget(TypedDict):
    value: int


class OrphanData(TypedDict):
    unused: int


class LegacyData(TypedDict):
    old: int


def describe(item: Item) -> str:
    print("LegacyData was removed in 2.0")
    print("Fraction of items shown")
    return str(item)


def narrow(value: object):
    return cast("CastTarget", value)


def clone(instance: T) -> T:
    return instance


def parse(raw: str) -> "UUID | None":
    return None
