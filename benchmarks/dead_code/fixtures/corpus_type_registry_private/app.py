from routes import ConversionTable

_router = ConversionTable()
_peer = ConversionTable()


@_router.accepts(str)
def _encode_alpha(value):
    return value.upper()


@_router.accepts(bytes)
def _encode_beta(value):
    return value.hex()


@_peer.accepts(str)
def _encode_gamma(value):
    return value.lower()


def _encode_delta(value):
    return repr(value)


print(_router.convert("record"))
