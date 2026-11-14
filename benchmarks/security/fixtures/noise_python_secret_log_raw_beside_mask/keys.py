import getpass


def mask(key):
    return key[:6] + "..." + key[-4:]


def store():
    value = getpass.getpass("API key (hidden): ").strip()
    print(f"masked {mask(value)} raw {value}")
