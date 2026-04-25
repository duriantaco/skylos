from markupsafe import Markup


def render_name(name):
    return Markup(f"<strong>{name}</strong>")
