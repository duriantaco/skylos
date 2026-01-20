from __future__ import annotations
import sqlite3
import hashlib
import pickle
import zlib
from pathlib import Path


class SkylosProcCache:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA temp_store=MEMORY;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self.conn.execute("PRAGMA wal_autocheckpoint=1000;")  # checkpt periodically
        self.conn.execute("PRAGMA journal_size_limit=67108864;")  # 64MB cap-ish

        self._init_schema()

    def _init_schema(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS proc_cache (
              file_path TEXT PRIMARY KEY,
              mtime_ns  INTEGER NOT NULL,
              size      INTEGER NOT NULL,
              sha256    TEXT NOT NULL,
              payload   BLOB NOT NULL
            );
            """
        )
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    def _hash_file(self, file_path):
        file_path = Path(file_path)
        st = file_path.stat()

        mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
        size = st.st_size

        h = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)

        return mtime_ns, size, h.hexdigest()

    def get(self, file_path):
        file_path = Path(file_path).resolve()
        try:
            st = file_path.stat()
        except FileNotFoundError:
            return None

        mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
        size = st.st_size

        row = self.conn.execute(
            "SELECT mtime_ns, size, sha256, payload FROM proc_cache WHERE file_path=?",
            (str(file_path),),
        ).fetchone()

        if not row:
            return None

        cached_mtime_ns, cached_size, cached_sha256, payload = row

        if cached_mtime_ns != mtime_ns or cached_size != size:
            return None

        _, _, sha256 = self._hash_file(file_path)
        if sha256 != cached_sha256:
            return None

        try:
            data = zlib.decompress(payload)
            return pickle.loads(data)
        except Exception:
            return None

    def put(self, file_path, result):
        file_path = Path(file_path).resolve()
        try:
            mtime_ns, size, sha256 = self._hash_file(file_path)
        except FileNotFoundError:
            return

        try:
            data = pickle.dumps(result, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            return

        payload = zlib.compress(data, level=6)

        self.conn.execute(
            """
            INSERT INTO proc_cache(file_path, mtime_ns, size, sha256, payload)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
              mtime_ns=excluded.mtime_ns,
              size=excluded.size,
              sha256=excluded.sha256,
              payload=excluded.payload
            """,
            (str(file_path), mtime_ns, size, sha256, payload),
        )
        self.conn.commit()
