import json
import os


class PanelClient:
    def __init__(self, panel, key):
        self.panel = panel
        self.key = key

    def sites(self):
        return {"panel": self.panel, "sites": []}


def build_client():
    key = os.environ.get("PANEL_API_KEY")
    return PanelClient("https://panel.example", key)


def pretty(value):
    return json.dumps(value, indent=2)


def main():
    client = build_client()
    result = client.sites()
    print(pretty(result))
