import pickle
import sqlite3


def search_users(request):
    term = request.args["q"]
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE name = '" + term + "'")


def restore_session(request):
    return pickle.loads(request.data)
