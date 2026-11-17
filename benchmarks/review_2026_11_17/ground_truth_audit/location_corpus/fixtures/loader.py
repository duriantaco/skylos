import yaml


def parse_untrusted(data):
    return yaml.load(data, Loader=yaml.Loader)


def parse_safe(data):
    return yaml.safe_load(data)
