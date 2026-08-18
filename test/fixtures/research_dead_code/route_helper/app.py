app = object()


@app.get("/")
def index():
    return render_dashboard()


def render_dashboard():
    return "ok"


def stale_helper():
    return "dead"
