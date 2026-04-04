from flask import Flask

app = Flask(__name__)


def list_users():
    return []


app.add_url_rule("/users", view_func=list_users)
