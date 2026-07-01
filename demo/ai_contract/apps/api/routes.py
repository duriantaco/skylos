class DemoApp:
    def route(self, _path):
        def decorator(handler):
            return handler

        return decorator


app = DemoApp()


@app.route("/admin")
def admin_dashboard(request):
    if not verify_acme_tenant(request):
        return {"error": "denied"}, 403
    return {"status": "ok"}
