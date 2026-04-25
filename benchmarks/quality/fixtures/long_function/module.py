def render_report(name):
    lines = []
    lines.append("start")
    lines.append(name)
    lines.append("middle")
    lines.append("detail")
    lines.append("summary")
    lines.append("end")
    return "\n".join(lines)


def tiny_helper():
    return "ok"
