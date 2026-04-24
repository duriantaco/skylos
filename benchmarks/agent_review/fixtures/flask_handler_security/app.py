from flask import Flask, request
import sqlite3
import subprocess


app = Flask(__name__)


@app.get("/user")
def user():
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = %s" % user_id
    return query


@app.get("/ls")
def ls():
    cmd = request.args["cmd"]
    return subprocess.check_output(cmd, shell=True)


@app.get("/safe")
def safe():
    user_id = request.args.get("id")
    conn = sqlite3.connect(":memory:")
    return conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    ).fetchall()
