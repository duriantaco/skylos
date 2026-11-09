from flask import Flask, request
import sqlite3

from app import run_query


app = Flask(__name__)
cursor = sqlite3.connect(":memory:").cursor()


@app.get("/users")
def users():
    return run_query(cursor, request.args["sql"], request.args.get("id"))
