# WARNING: INTENTIONALLY VULNERABLE DEMO. DO NOT USE IN PROD.
from flask import Flask, request
import sqlite3, os, subprocess, requests, hashlib, pickle, yaml

# Optional libs used in raw-SQL examples (AST-based scan; imports need not resolve at runtime)
import pandas as pd
import sqlalchemy as sa

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

# 1) SQL injection (cursor: tainted/interpolated SQL) → SKY-D211
@app.get("/find")
def find_user():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    sql = f"SELECT id,name,score FROM users WHERE name = '{name}'"  # SKY-D211
    rows = cur.execute(sql).fetchall()
    return {"rows": rows}

# 2) SQL injection (cursor: identifier injection) → SKY-D218 (your “identifier” rule)
@app.get("/dump")
def dump_table():
    tbl = request.args.get("tbl", "users")
    cur = get_db().cursor()
    sql = f"SELECT * FROM {tbl}"  # SKY-D218
    rows = cur.execute(sql).fetchall()
    return {"rows": rows}

# 3) SQL injection (raw APIs): sqlalchemy.text / pandas.read_sql / Django-like raw → SKY-D217
@app.get("/report")
def report():
    q = request.args.get("q", "")
    conn = get_db()
    # sqlalchemy.text
    sa.text("SELECT * FROM users WHERE name = '" + q + "'")  # SKY-D217
    # pandas.read_sql
    pd.read_sql(f"SELECT * FROM users WHERE name='{q}'", conn)  # SKY-D217
    # Django-like .objects.raw pattern (simulated)
    class User:
        class objects:
            @staticmethod
            def raw(sql):  # no-op; just for pattern
                return []
    User.objects.raw("SELECT * FROM users WHERE name = '" + q + "'")  # SKY-D217
    return {"ok": True}

# 4) Command injection (tainted shell command) → SKY-D212
@app.get("/zip")
def zip_folder():
    path = request.args.get("path", ".")
    os.system(f"zip -r out.zip {path}")  # SKY-D212
    subprocess.run("ls -l " + path, shell=True)  # SKY-D212
    return {"ok": True}

# 5) SSRF + TLS disabled → SKY-D216 (SSRF) and SKY-D208 (verify=False)
@app.get("/fetch")
def fetch():
    url = request.args.get("url", "http://127.0.0.1:80")
    r = requests.get(url, timeout=2, verify=False)  # SKY-D216 + SKY-D208
    return {"status": r.status_code if r else 0}

# 6) Path traversal (user-controlled path) → SKY-D215
@app.get("/read")
def read_file():
    p = request.args.get("p", "README.md")
    with open(p, "r", encoding="utf-8", errors="ignore") as f:  # SKY-D215
        return {"content": f.read(200)}

# 7) eval / exec → SKY-D201 / SKY-D202
@app.get("/eval")
def do_eval():
    code = request.args.get("code", "1+1")
    eval(code)  # SKY-D201
    exec("print('hi')")  # SKY-D202
    return {"ok": True}

# 8) pickle.loads / pickle.load (untrusted) → SKY-D204 / SKY-D203
@app.get("/pickle")
def do_pickle():
    data = request.args.get("data", "80034b012e")  # hex for b'\x80\x03K\x01.'
    try:
        blob = bytes.fromhex(data)
    except Exception:
        blob = b"\x80\x03K\x01."
    pickle.loads(blob)  # SKY-D204
    # simulate file load (won't run; here just to trigger static pattern)
    # with open("dump.pkl", "rb") as fh:
    #     pickle.load(fh)  # SKY-D203
    return {"ok": True}

# 9) yaml.load without SafeLoader → SKY-D205
@app.get("/yaml")
def do_yaml():
    doc = request.args.get("doc", "a: 1")
    yaml.load(doc)  # SKY-D205
    return {"ok": True}

# 10) Weak hashes → SKY-D206 / SKY-D207
@app.get("/hash")
def do_hash():
    data = b"hello"
    hashlib.md5(data).hexdigest()   # SKY-D206
    hashlib.sha1(data).hexdigest()  # SKY-D207
    return {"ok": True}

if __name__ == "__main__":
    app.run(debug=True)
