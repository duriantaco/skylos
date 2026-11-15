import getpass


def redact(key):
    return key.replace("-", "")


def store():
    value = getpass.getpass("API key (hidden): ").strip()
    print(f"stored {redact(value)}")
