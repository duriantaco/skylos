from flask import Flask, request
import sqlite3, os, subprocess, requests, hashlib, pickle, yaml
import pandas as pd
import sqlalchemy as sa
import json
from pathlib import Path

THIS_FILE = Path(__file__).resolve()

from skylos.analyzer import analyze as skylos_analyze

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, score INT);
        INSERT OR IGNORE INTO users(id,name,score) VALUES
          (1,'alice',10),(2,'bob',20),(3,'carol',30);
    """)
    conn.commit()
    return conn


@app.get("/find")
def find_user():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    sql = f"SELECT id,name,score FROM users WHERE name = '{name}'"
    rows = cur.execute(sql).fetchall()
    return {"rows": rows}

@app.get("/find2")
def find_user2():
    name = request.args.get("name", "")
    cur = get_db().cursor()

    sql = f"SELECT id,name,score FROM users WHERE name = '{name}'"
    rows = cur.execute(sql).fetchall()
    return {"rows": rows}

@app.get("/find3")
def find_user3():
    name = request.args.get("name", "")
    cur = get_db().cursor()

    sql = f"SELECT id,name,score FROM users WHERE name = '{name}'"
    rows = cur.execute(sql).fetchall()
    return {"rows": rows}

@app.get("/find4")
def find_user4():
    name = request.args.get("name", "")
    cur = get_db().cursor()

    sql = f"SELECT id,name,score FROM users WHERE name = '{name}'"
    rows = cur.execute(sql).fetchall()
    return {"rows": rows}


@app.get("/dump")
def dump_table():
    tbl = request.args.get("tbl", "users")
    cur = get_db().cursor()
    sql = f"SELECT * FROM {tbl}"
    rows = cur.execute(sql).fetchall()
    return {"rows": rows}


@app.get("/report")
def report():
    q = request.args.get("q", "")
    conn = get_db()
    sa.text("SELECT * FROM users WHERE name = '" + q + "'")
    pd.read_sql(f"SELECT * FROM users WHERE name='{q}'", conn)

    class User:
        class objects:
            @staticmethod
            def raw(sql):
                return []

    User.objects.raw("SELECT * FROM users WHERE name = '" + q + "'")
    return {"ok": True}


@app.get("/zip")
def zip_folder():
    path = request.args.get("path", ".")
    os.system(f"zip -r out.zip {path}")
    subprocess.run("ls -l " + path, shell=True)
    return {"ok": True}


@app.get("/fetch")
def fetch():
    url = request.args.get("url", "http://127.0.0.1:80")
    r = requests.get(url, timeout=2, verify=False)
    return {"status": r.status_code if r else 0}


@app.get("/read")
def read_file():
    p = request.args.get("p", "README.md")
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        return {"content": f.read(200)}


@app.get("/eval")
def do_eval():
    code = request.args.get("code", "1+1")
    eval(code)
    exec("print('hi')")
    return {"ok": True}


@app.get("/yaml")
def do_yaml():
    doc = request.args.get("doc", "a: 1")
    yaml.load(doc)
    return {"ok": True}


@app.get("/hash")
def do_hash():
    data = b"hello"
    hashlib.md5(data).hexdigest()
    hashlib.sha1(data).hexdigest()
    return {"ok": True}

def code_old():

    unused_var = "I am ghost"

    print("Starting App...")
    result = 10 + "20"

@app.get("/hashes")
def do_hashes():
    datas = b"hello123"
    hashlib.md5(datas).hexdigest()
    hashlib.sha1(datas).hexdigest()
    return {"ok": True}

def code_olds():

    unused_vars = "I am ghost"

    print("Starting App...")
    results = 10 + "20"

aws_key = "AKIA1234567890DUMMYKEY"

def omg_quality(x, ys):
    total = 0
    for y in ys:
        if y > 0:
            total += y
        else:
            total -= y

    if total > 10 and x:
        for i in range(5):
            if i % 2 == 0:
                total += i
            else:
                total -= i

    try:
        while total < 100:
            if total % 3 == 0 and total % 5 == 0:
                break
            if total % 2 == 0:
                total += 7
            else:
                total += 3
    except Exception:
        total = -1

    return total


def main():
    result_json = skylos_analyze(str(THIS_FILE), conf=0, enable_quality=True)
    data = json.loads(result_json)

    assert "quality" in data, "Expected 'quality' key in analyzer result"
    assert data["analysis_summary"].get("quality_count", 0) >= 1, (
        "Expected quality_count >= 1"
    )

    findings = data["quality"]
    matches = [
        q
        for q in findings
        if (
            q.get("name", "").endswith(".omg_quality")
            or q.get("simple_name") == "omg_quality"
        )
    ]
    assert matches, "Expected a quality finding for omg_quality"

    q = matches[0]
    complexity = int(q.get("complexity", -1))
    assert complexity >= 10, f"Expected complexity >= 10, got {complexity}"

    print("OK! Skylos quality rule fired:")
    print(f" kind: {q.get('kind', '(missing)')}")
    print(f" name: {q.get('name') or q.get('simple_name')}")
    print(f" file:line : {q.get('file')}:{q.get('line')}")
    print(f" complexity: {complexity}")
    print(f" length : {q.get('length')}")


if __name__ == "__main__":
    main()
