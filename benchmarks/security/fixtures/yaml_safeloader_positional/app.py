import yaml


def parse_config(payload):
    return yaml.load(payload, yaml.SafeLoader)
