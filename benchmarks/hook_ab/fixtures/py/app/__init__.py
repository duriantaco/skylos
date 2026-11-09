import os

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

    from app import routes

    app.register_blueprint(routes.bp)
    return app
