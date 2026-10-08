import hashlib
import hmac
import json
import logging
import sqlite3
import threading
import time

GENESIS = "0" * 64


class AuditLog:
    """Append-only, hash-chained, HMAC-signed log.

    Editing any row breaks the chain; verify() reports the first bad id.
    # ponytail: HMAC is symmetric and tail truncation is undetectable from the file alone –
    # upgrade to Ed25519 + periodically anchor head() off-box when auditors require non-repudiation.
    """

    def __init__(self, path: str, key: bytes):
        if len(key) < 16:
            raise ValueError("SENTINEL_AUDIT_KEY must be at least 16 bytes")
        self._key = key
        self._lock = threading.Lock()
        self._subs: list = []
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS entries(
              id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, event TEXT NOT NULL,
              prev TEXT NOT NULL, hash TEXT NOT NULL, sig TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS no_update BEFORE UPDATE ON entries
              BEGIN SELECT RAISE(ABORT, 'append-only'); END;
            CREATE TRIGGER IF NOT EXISTS no_delete BEFORE DELETE ON entries
              BEGIN SELECT RAISE(ABORT, 'append-only'); END;
            """
        )

    @staticmethod
    def _digest(prev: str, ts: float, event: str) -> str:
        return hashlib.sha256(f"{prev}|{ts!r}|{event}".encode()).hexdigest()

    def _sign(self, h: str) -> str:
        return hmac.new(self._key, h.encode(), "sha256").hexdigest()

    def subscribe(self, fn) -> None:
        """fn(event) runs after every append, outside the lock. Errors are logged, never raised."""
        self._subs.append(fn)

    def events(self):
        for ts, ev in self.db.execute("SELECT ts, event FROM entries ORDER BY id"):
            yield ts, json.loads(ev)

    def recent(self, type_: str, limit: int = 50) -> list[dict]:
        rows = self.db.execute("SELECT event FROM entries WHERE event LIKE ? ORDER BY id DESC LIMIT ?",
                               (f'%"type":"{type_}"%', limit)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def head(self) -> str:
        row = self.db.execute("SELECT hash FROM entries ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def append(self, event: dict) -> str:
        ev = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)
        with self._lock:
            prev, ts = self.head(), time.time()
            h = self._digest(prev, ts, ev)
            self.db.execute(
                "INSERT INTO entries(ts,event,prev,hash,sig) VALUES(?,?,?,?,?)",
                (ts, ev, prev, h, self._sign(h)),
            )
            self.db.commit()
        for fn in self._subs:
            try:
                fn(event)
            except Exception:
                logging.getLogger("sentinel.audit").exception("audit subscriber failed")
        return h

    def verify(self) -> tuple[bool, int | None]:
        prev = GENESIS
        rows = self.db.execute("SELECT id,ts,event,prev,hash,sig FROM entries ORDER BY id")
        for id_, ts, ev, p, h, sig in rows:
            if p != prev or h != self._digest(prev, ts, ev) or not hmac.compare_digest(sig, self._sign(h)):
                return False, id_
            prev = h
        return True, None
