from collections import OrderedDict


_MAX_ENTRIES = 1024
_ENTRIES = OrderedDict()


def get_or_set(key, factory):
    if key in _ENTRIES:
        _ENTRIES.move_to_end(key)
        return _ENTRIES[key]
    value = factory()
    if len(_ENTRIES) >= _MAX_ENTRIES:
        _ENTRIES.popitem(last=False)
    _ENTRIES[key] = value
    return value
