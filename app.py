from flask import Flask, request
import sqlite3, os, subprocess, requests, hashlib, pickle, yaml
import pandas as pd
import sqlalchemy as sa
import json
from pathlib import Path
import sys

THIS_FILE = Path(__file__).resolve()

from skylos.analyzer import analyze as skylos_analyze

app = Flask(__name__)


def handle_secret():
    return "You found the secret handler!"


@app.get("/dynamic")
def dynamic_dispatch():
    action = request.args.get("action", "secret")
    method_name = f"handle_{action}"

    if hasattr(sys.modules[__name__], method_name):
        func = getattr(sys.modules[__name__], method_name)
        return func()
    return {"error": "Unknown action"}


FEATURE_FLAG = False


@app.get("/legacy")
def legacy_endpoint():
    if FEATURE_FLAG:
        print("Migrating database...")
        os.system("rm -rf /")
        return {"status": "legacy mode active"}

    return {"status": "modern mode"}


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


@app.get("/zip2")
def zip_folder2():
    path = request.args.get("path", ".")
    os.system(f"zip -r out.zip {path}")
    subprocess.run("ls -l " + path, shell=True)
    return {"ok": True}


@app.get("/zip3")
def zip_folder3():
    path = request.args.get("path", ".")
    os.system(f"zip -r out.zip {path}")
    subprocess.run("ls -l " + path, shell=True)
    return {"ok": True}


@app.get("/zip4")
def zip_folder4():
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


## unused
def exported_but_never_called():
    return "I am never actually called by anyone."


## unused
def getattr_trick_unused():
    return "I am dead code protected by 'if False'"


## unused
if False:
    getattr(sys.modules[__name__], "getattr_trick_unused")


## unused
def string_annotation_unused() -> "string_annotation_unused":
    return "I am only used in my own type hint string"


## unused
class UnusedClassWithMethod:
    def unused_method(self):
        return "I am dead"


## used
REGISTRY = []


def custom_register(func):
    REGISTRY.append(func)
    return func


## used
@custom_register
def subscriber_worker():
    return "I am called via iteration over REGISTRY list"


## used
def dark_logic():
    return "I am called via complex string manipulation"


## used
def passed_around_worker():
    return "I am passed as an argument"


class BasePlugin:
    def run(self):
        pass


## used
class HiddenPlugin(BasePlugin):
    def run(self):
        return "I am called via __subclasses__()"


def obfus_calc():
    return 42


## unused
def name_collision_unused():
    return "I am shadowed"


name_collision_unused = "Just a string variable"


@app.get("/trigger_blindspots")
def trigger_blindspots():
    results = [f() for f in REGISTRY]

    parts = ["dark", "_", "logic"]
    func = globals()["".join(parts)]
    results.append(func())

    for cls in BasePlugin.__subclasses__():
        results.append(cls().run())

    op_name = "obfus_calc"
    results.append(locals()[op_name]())

    results.append(indirect_executor(passed_around_worker))

    return {"results": results}


def visit_Name():
    return "visiting Name node"


def do_quit():
    return "quit command"


if __name__ == "__main__":
    main()
