from peers import Peer


class OutputBase:
    def render(self, result):
        raise NotImplementedError


class Formatter(OutputBase):
    def render_a(self, value):
        return value * 2

    def render_b(self, value):
        return value * 3

    def render_c(self, value):
        return value * 4

    MODES: dict[str, tuple[str, int]] = {
        "a": ("render_a", 1),
        "b": ("render_b", 0),
    }

    def render(self, result):
        value = result.get("value")
        if value is None:
            return None
        selected = Formatter.MODES.get(result.get("mode"))
        if selected is not None:
            method = getattr(self, selected[0])
            return method(value)
        return value


print(Formatter().render({"value": 2, "mode": input()}))
Peer()
