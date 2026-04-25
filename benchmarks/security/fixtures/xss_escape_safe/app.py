import html

from markupsafe import Markup


def render_name(name):
    escaped = html.escape(name)
    return Markup(f"<strong>{escaped}</strong>")
