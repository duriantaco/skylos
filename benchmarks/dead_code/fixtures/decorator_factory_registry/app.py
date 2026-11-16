import sys

from routes import ConversionTable, Tagger

table = ConversionTable()
tagger = Tagger()


@table.accepts("upper")
def _encode_upper(value):
    return value.upper()


@table.accepts("hex")
def _encode_hex(value):
    return value.encode().hex()


@tagger.label("unused")
def _tagged_only(value):
    return value


def _never_registered(value):
    return repr(value)


print(table.convert(sys.argv[1], "record"), tagger.count)
