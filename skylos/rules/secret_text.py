"""Interpret explicitly encoded secret-file text without guessing byte order."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretFileText:
    text: str = field(repr=False)
    encoding: str | None = None


def decode_secret_file_text(data: bytes, *, strict_utf8: bool) -> SecretFileText | None:
    # UTF-32LE starts with the UTF-16LE mark. Recognize the longer signatures
    # first so unsupported encodings never become interleaved NUL text.
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return None
    encoding = None
    if data.startswith(b"\xff\xfe"):
        encoding = "utf16le"
        codec = "utf-16-le"
    elif data.startswith(b"\xfe\xff"):
        encoding = "utf16be"
        codec = "utf-16-be"
    else:
        codec = "utf-8"
    try:
        if encoding is not None:
            text = data[2:].decode(codec, "strict")
            if "\x00" in text:
                return None
        else:
            text = data.decode(codec, "strict" if strict_utf8 else "ignore")
    except UnicodeError:
        return None
    return SecretFileText(text.replace("\r\n", "\n").replace("\r", "\n"), encoding)
