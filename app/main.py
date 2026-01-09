import json
import os
import sqlite3
import time
import uuid
import base64
import re
from datetime import datetime, timezone
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, HTTPException, Request, Response

TTL_SECONDS = 48 * 60 * 60
KDF_ITERATIONS = int(os.environ.get("KDF_ITERATIONS", "200000"))

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

app = FastAPI(title="GetBack API")


UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _now_ts() -> int:
    return int(time.time())


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _metric_inc(conn: sqlite3.Connection, key: str, amount: int = 1) -> None:
    conn.execute(
        """
        INSERT INTO metrics(key, value) VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value = value + excluded.value
        """,
        (key, amount),
    )


def _route_key(path: str) -> str:
    if path == "/":
        return "/"
    if path.startswith("/status"):
        return "/status"
    if path.startswith("/"):
        rest = path[1:]
        if UUID_RE.match(rest):
            return "/{uuid}"
    return path


def _get_read_passphrase(request: Request) -> Optional[str]:
    value = request.headers.get("x-read-passphrase")
    if value is None:
        return None
    value = value.strip()
    return value or None


def _get_write_passphrase(request: Request) -> Optional[str]:
    value = request.headers.get("x-write-passphrase")
    if value is None:
        return None
    value = value.strip()
    return value or None


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32,
                     salt=salt, iterations=iterations)
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt(plaintext: bytes, passphrase: str) -> Tuple[str, str, str, int]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(passphrase, salt, KDF_ITERATIONS)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return _b64e(ciphertext), _b64e(salt), _b64e(nonce), KDF_ITERATIONS


def _decrypt(ciphertext_b64: str, passphrase: str, salt_b64: str, nonce_b64: str, iterations: int) -> bytes:
    ciphertext = _b64d(ciphertext_b64)
    salt = _b64d(salt_b64)
    nonce = _b64d(nonce_b64)
    key = _derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def _wrap_data_key(data_key: bytes, passphrase: str) -> Tuple[str, str, str, int]:
    return _encrypt(data_key, passphrase)


def _unwrap_data_key(wrapped_b64: str, passphrase: str, salt_b64: str, nonce_b64: str, iterations: int) -> bytes:
    return _decrypt(wrapped_b64, passphrase, salt_b64, nonce_b64, iterations)


def _encrypt_payload_with_data_key(payload: bytes, data_key: bytes) -> Tuple[str, str]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(data_key)
    ciphertext = aesgcm.encrypt(nonce, payload, None)
    return _b64e(ciphertext), _b64e(nonce)


def _decrypt_payload_with_data_key(ciphertext_b64: str, nonce_b64: str, data_key: bytes) -> bytes:
    ciphertext = _b64d(ciphertext_b64)
    nonce = _b64d(nonce_b64)
    aesgcm = AESGCM(data_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def _init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                content_type TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                encrypted INTEGER NOT NULL DEFAULT 0,
                salt_b64 TEXT,
                nonce_b64 TEXT,
                kdf_iterations INTEGER,
                payload_nonce_b64 TEXT,
                wrapped_key_read_b64 TEXT,
                wrapped_key_read_salt_b64 TEXT,
                wrapped_key_read_nonce_b64 TEXT,
                wrapped_key_read_kdf_iterations INTEGER,
                wrapped_key_write_b64 TEXT,
                wrapped_key_write_salt_b64 TEXT,
                wrapped_key_write_nonce_b64 TEXT,
                wrapped_key_write_kdf_iterations INTEGER
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_items_expires_at ON items(expires_at)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            )
            """
        )

        cols = {row["name"] for row in conn.execute(
            "PRAGMA table_info(items)").fetchall()}
        if "encrypted" not in cols:
            conn.execute(
                "ALTER TABLE items ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0")
        if "salt_b64" not in cols:
            conn.execute("ALTER TABLE items ADD COLUMN salt_b64 TEXT")
        if "nonce_b64" not in cols:
            conn.execute("ALTER TABLE items ADD COLUMN nonce_b64 TEXT")
        if "kdf_iterations" not in cols:
            conn.execute("ALTER TABLE items ADD COLUMN kdf_iterations INTEGER")
        if "payload_nonce_b64" not in cols:
            conn.execute("ALTER TABLE items ADD COLUMN payload_nonce_b64 TEXT")
        if "wrapped_key_read_b64" not in cols:
            conn.execute(
                "ALTER TABLE items ADD COLUMN wrapped_key_read_b64 TEXT")
        if "wrapped_key_read_salt_b64" not in cols:
            conn.execute(
                "ALTER TABLE items ADD COLUMN wrapped_key_read_salt_b64 TEXT")
        if "wrapped_key_read_nonce_b64" not in cols:
            conn.execute(
                "ALTER TABLE items ADD COLUMN wrapped_key_read_nonce_b64 TEXT")
        if "wrapped_key_read_kdf_iterations" not in cols:
            conn.execute(
                "ALTER TABLE items ADD COLUMN wrapped_key_read_kdf_iterations INTEGER")
        if "wrapped_key_write_b64" not in cols:
            conn.execute(
                "ALTER TABLE items ADD COLUMN wrapped_key_write_b64 TEXT")
        if "wrapped_key_write_salt_b64" not in cols:
            conn.execute(
                "ALTER TABLE items ADD COLUMN wrapped_key_write_salt_b64 TEXT")
        if "wrapped_key_write_nonce_b64" not in cols:
            conn.execute(
                "ALTER TABLE items ADD COLUMN wrapped_key_write_nonce_b64 TEXT")
        if "wrapped_key_write_kdf_iterations" not in cols:
            conn.execute(
                "ALTER TABLE items ADD COLUMN wrapped_key_write_kdf_iterations INTEGER")


def _cleanup_expired(conn: sqlite3.Connection) -> None:
    now = _now_ts()
    conn.execute("DELETE FROM items WHERE expires_at <= ?", (now,))


def _normalize_payload(request: Request, raw: bytes) -> Tuple[str, str]:
    content_type = (request.headers.get("content-type") or "").lower()

    if "application/json" in content_type:
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise HTTPException(
                status_code=400, detail=f"Invalid JSON: {e}") from e
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False), "application/json"

    if "text/plain" in content_type:
        try:
            text = raw.decode("utf-8")
        except Exception as e:
            raise HTTPException(
                status_code=400, detail=f"Invalid text encoding: {e}") from e
        return text, "text/plain"

    raise HTTPException(
        status_code=415, detail="Only application/json or text/plain is accepted")


@app.on_event("startup")
def on_startup() -> None:
    _init_db()
    app.state.started_at = datetime.now(timezone.utc)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = int((time.perf_counter() - start) * 1000)

    method = request.method.upper()
    route = _route_key(request.url.path)
    status = int(getattr(response, "status_code", 0) or 0)
    status_class = f"{status // 100}xx" if status else "unknown"

    try:
        with _connect() as conn:
            _metric_inc(conn, "req_total")
            _metric_inc(conn, f"req_method:{method}")
            _metric_inc(conn, f"req_route:{route}")
            _metric_inc(conn, f"req_route_method:{route}:{method}")
            _metric_inc(conn, f"req_status_class:{status_class}")
            _metric_inc(conn, f"req_status:{status}")
            _metric_inc(conn, f"req_route_status:{route}:{status}")
            _metric_inc(conn, "resp_ms_total", duration_ms)
    except Exception:
        pass

    return response


def _get_metrics_snapshot(conn: sqlite3.Connection):
    rows = conn.execute("SELECT key, value FROM metrics").fetchall()
    return {row["key"]: int(row["value"]) for row in rows}


def _get_item_stats(conn: sqlite3.Connection):
    now = _now_ts()
    _cleanup_expired(conn)
    total = int(
        conn.execute(
            "SELECT COUNT(*) AS c FROM items WHERE expires_at > ?", (now,)).fetchone()["c"]
    )
    encrypted = int(
        conn.execute(
            "SELECT COUNT(*) AS c FROM items WHERE expires_at > ? AND encrypted = 1", (now,)
        ).fetchone()["c"]
    )
    return {"items_total": total, "items_encrypted": encrypted}


@app.get("/status.json")
def status_json():
    started_at = getattr(app.state, "started_at", None)
    now_dt = datetime.now(timezone.utc)
    uptime_seconds = int(
        (now_dt - started_at).total_seconds()) if started_at else None

    with _connect() as conn:
        metrics = _get_metrics_snapshot(conn)
        item_stats = _get_item_stats(conn)

    db_size_bytes = None
    try:
        if os.path.exists(DB_PATH):
            db_size_bytes = os.path.getsize(DB_PATH)
    except Exception:
        db_size_bytes = None

    return {
        "uptime_seconds": uptime_seconds,
        "ttl_seconds": TTL_SECONDS,
        "db_path": DB_PATH,
        "db_size_bytes": db_size_bytes,
        "items": item_stats,
        "metrics": metrics,
    }


@app.get("/status")
def status_page():
    data = status_json()
    items = data["items"]
    metrics = data["metrics"]

    def _v(key: str) -> int:
        return int(metrics.get(key, 0))

    html = """
<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>GetBack API Status</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 24px; line-height: 1.4; }
      h1 { margin: 0 0 12px 0; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
      .card { border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px; }
      .k { color: #6b7280; font-size: 12px; }
      .v { font-size: 18px; font-weight: 600; }
      table { width: 100%; border-collapse: collapse; }
      th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #f0f2f5; }
      code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <h1>GetBack API Status</h1>
    <div class=\"grid\">
      <div class=\"card\"><div class=\"k\">Uptime (seconds)</div><div class=\"v\">{uptime}</div></div>
      <div class=\"card\"><div class=\"k\">TTL (seconds)</div><div class=\"v\">{ttl}</div></div>
      <div class=\"card\"><div class=\"k\">Items stored</div><div class=\"v\">{items_total}</div></div>
      <div class=\"card\"><div class=\"k\">Items encrypted</div><div class=\"v\">{items_encrypted}</div></div>
      <div class=\"card\"><div class=\"k\">Requests total</div><div class=\"v\">{req_total}</div></div>
      <div class=\"card\"><div class=\"k\">Avg response time (ms)</div><div class=\"v\">{avg_ms}</div></div>
    </div>

    <h2>Requests by route</h2>
    <table>
      <thead>
        <tr><th>Route</th><th>Count</th></tr>
      </thead>
      <tbody>
        <tr><td><code>/</code></td><td>{r_root}</td></tr>
        <tr><td><code>/{{uuid}}</code></td><td>{r_uuid}</td></tr>
        <tr><td><code>/status</code></td><td>{r_status}</td></tr>
      </tbody>
    </table>

    <p>JSON: <a href=\"/status.json\"><code>/status.json</code></a></p>
  </body>
</html>
"""

    req_total = _v("req_total")
    resp_ms_total = _v("resp_ms_total")
    avg_ms = int(resp_ms_total / req_total) if req_total else 0

    return Response(
        content=html.format(
            uptime=data["uptime_seconds"] if data["uptime_seconds"] is not None else "-",
            ttl=data["ttl_seconds"],
            items_total=items["items_total"],
            items_encrypted=items["items_encrypted"],
            req_total=req_total,
            avg_ms=avg_ms,
            r_root=_v("req_route:/"),
            r_uuid=_v("req_route:/{uuid}"),
            r_status=_v("req_route:/status"),
        ),
        media_type="text/html",
    )


@app.post("/")
async def create_item(request: Request):
    raw = await request.body()
    payload, content_type = _normalize_payload(request, raw)
    read_passphrase = _get_read_passphrase(request)
    write_passphrase = _get_write_passphrase(request)

    item_id = str(uuid.uuid4())
    now = _now_ts()
    expires_at = now + TTL_SECONDS

    encrypted = 0
    stored_payload = payload

    payload_nonce_b64 = None
    wrapped_key_read_b64 = None
    wrapped_key_read_salt_b64 = None
    wrapped_key_read_nonce_b64 = None
    wrapped_key_read_kdf_iterations = None
    wrapped_key_write_b64 = None
    wrapped_key_write_salt_b64 = None
    wrapped_key_write_nonce_b64 = None
    wrapped_key_write_kdf_iterations = None

    if read_passphrase is not None or write_passphrase is not None:
        if read_passphrase is None or write_passphrase is None:
            raise HTTPException(
                status_code=400, detail="For encryption, both X-Read-Passphrase and X-Write-Passphrase are required")

        data_key = os.urandom(32)
        ciphertext_b64, payload_nonce_b64 = _encrypt_payload_with_data_key(
            payload.encode("utf-8"), data_key)
        stored_payload = ciphertext_b64
        encrypted = 1

        wrapped_key_read_b64, wrapped_key_read_salt_b64, wrapped_key_read_nonce_b64, wrapped_key_read_kdf_iterations = _wrap_data_key(
            data_key, read_passphrase
        )
        wrapped_key_write_b64, wrapped_key_write_salt_b64, wrapped_key_write_nonce_b64, wrapped_key_write_kdf_iterations = _wrap_data_key(
            data_key, write_passphrase
        )

    with _connect() as conn:
        _cleanup_expired(conn)
        conn.execute(
            """
            INSERT INTO items(
              id, payload, content_type, created_at, updated_at, expires_at,
              encrypted, payload_nonce_b64,
              wrapped_key_read_b64, wrapped_key_read_salt_b64, wrapped_key_read_nonce_b64, wrapped_key_read_kdf_iterations,
              wrapped_key_write_b64, wrapped_key_write_salt_b64, wrapped_key_write_nonce_b64, wrapped_key_write_kdf_iterations
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item_id,
                stored_payload,
                content_type,
                now,
                now,
                expires_at,
                encrypted,
                payload_nonce_b64,
                wrapped_key_read_b64,
                wrapped_key_read_salt_b64,
                wrapped_key_read_nonce_b64,
                wrapped_key_read_kdf_iterations,
                wrapped_key_write_b64,
                wrapped_key_write_salt_b64,
                wrapped_key_write_nonce_b64,
                wrapped_key_write_kdf_iterations,
            ),
        )

    return {"id": item_id}


def _get_item(conn: sqlite3.Connection, item_id: str) -> Optional[sqlite3.Row]:
    _cleanup_expired(conn)
    row = conn.execute(
        """
        SELECT id, payload, content_type, expires_at,
               encrypted, payload_nonce_b64,
               wrapped_key_read_b64, wrapped_key_read_salt_b64, wrapped_key_read_nonce_b64, wrapped_key_read_kdf_iterations,
               wrapped_key_write_b64, wrapped_key_write_salt_b64, wrapped_key_write_nonce_b64, wrapped_key_write_kdf_iterations
        FROM items WHERE id = ?
        """,
        (item_id,),
    ).fetchone()
    return row


@app.get("/{item_id}")
def read_item(item_id: str, request: Request):
    with _connect() as conn:
        row = _get_item(conn, item_id)

    if row is None:
        raise HTTPException(status_code=404, detail="Not found")

    if int(row["encrypted"] or 0) == 1:
        read_passphrase = _get_read_passphrase(request)

        if row["wrapped_key_read_b64"] is None:
            raise HTTPException(status_code=404, detail="Not found")

        if read_passphrase is None:
            raise HTTPException(status_code=404, detail="Not found")
        try:
            data_key = _unwrap_data_key(
                row["wrapped_key_read_b64"],
                read_passphrase,
                row["wrapped_key_read_salt_b64"],
                row["wrapped_key_read_nonce_b64"],
                int(row["wrapped_key_read_kdf_iterations"] or KDF_ITERATIONS),
            )
            plaintext = _decrypt_payload_with_data_key(
                row["payload"], row["payload_nonce_b64"], data_key)
        except Exception as exc:
            raise HTTPException(
                status_code=404, detail="Not found") from exc
        return Response(content=plaintext, media_type=row["content_type"])

    return Response(content=row["payload"], media_type=row["content_type"])


@app.post("/{item_id}")
async def update_item(item_id: str, request: Request):
    raw = await request.body()
    payload, content_type = _normalize_payload(request, raw)
    read_passphrase = _get_read_passphrase(request)
    write_passphrase = _get_write_passphrase(request)

    now = _now_ts()
    expires_at = now + TTL_SECONDS

    with _connect() as conn:
        row = _get_item(conn, item_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Not found")

        if int(row["encrypted"] or 0) == 1:
            if row["wrapped_key_write_b64"] is None:
                raise HTTPException(status_code=404, detail="Not found")
            if write_passphrase is None:
                raise HTTPException(status_code=404, detail="Not found")
            try:
                data_key = _unwrap_data_key(
                    row["wrapped_key_write_b64"],
                    write_passphrase,
                    row["wrapped_key_write_salt_b64"],
                    row["wrapped_key_write_nonce_b64"],
                    int(row["wrapped_key_write_kdf_iterations"]
                        or KDF_ITERATIONS),
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=404, detail="Not found") from exc

            ciphertext_b64, payload_nonce_b64 = _encrypt_payload_with_data_key(
                payload.encode("utf-8"), data_key)
            conn.execute(
                """
                UPDATE items
                SET payload = ?, payload_nonce_b64 = ?, content_type = ?, updated_at = ?, expires_at = ?
                WHERE id = ?
                """,
                (ciphertext_b64, payload_nonce_b64,
                 content_type, now, expires_at, item_id),
            )
            return {"id": item_id}

        if read_passphrase is not None or write_passphrase is not None:
            if read_passphrase is None or write_passphrase is None:
                raise HTTPException(
                    status_code=400, detail="For encryption, both X-Read-Passphrase and X-Write-Passphrase are required")

            data_key = os.urandom(32)
            ciphertext_b64, payload_nonce_b64 = _encrypt_payload_with_data_key(
                payload.encode("utf-8"), data_key)
            wrapped_key_read_b64, wrapped_key_read_salt_b64, wrapped_key_read_nonce_b64, wrapped_key_read_kdf_iterations = _wrap_data_key(
                data_key, read_passphrase
            )
            wrapped_key_write_b64, wrapped_key_write_salt_b64, wrapped_key_write_nonce_b64, wrapped_key_write_kdf_iterations = _wrap_data_key(
                data_key, write_passphrase
            )

            conn.execute(
                """
                UPDATE items
                SET payload = ?, payload_nonce_b64 = ?, content_type = ?, updated_at = ?, expires_at = ?,
                    encrypted = 1,
                    wrapped_key_read_b64 = ?, wrapped_key_read_salt_b64 = ?, wrapped_key_read_nonce_b64 = ?, wrapped_key_read_kdf_iterations = ?,
                    wrapped_key_write_b64 = ?, wrapped_key_write_salt_b64 = ?, wrapped_key_write_nonce_b64 = ?, wrapped_key_write_kdf_iterations = ?
                WHERE id = ?
                """,
                (
                    ciphertext_b64,
                    payload_nonce_b64,
                    content_type,
                    now,
                    expires_at,
                    wrapped_key_read_b64,
                    wrapped_key_read_salt_b64,
                    wrapped_key_read_nonce_b64,
                    wrapped_key_read_kdf_iterations,
                    wrapped_key_write_b64,
                    wrapped_key_write_salt_b64,
                    wrapped_key_write_nonce_b64,
                    wrapped_key_write_kdf_iterations,
                    item_id,
                ),
            )
            return {"id": item_id}

        conn.execute(
            """
            UPDATE items
            SET payload = ?, content_type = ?, updated_at = ?, expires_at = ?,
                encrypted = 0,
                payload_nonce_b64 = NULL,
                wrapped_key_read_b64 = NULL, wrapped_key_read_salt_b64 = NULL, wrapped_key_read_nonce_b64 = NULL, wrapped_key_read_kdf_iterations = NULL,
                wrapped_key_write_b64 = NULL, wrapped_key_write_salt_b64 = NULL, wrapped_key_write_nonce_b64 = NULL, wrapped_key_write_kdf_iterations = NULL
            WHERE id = ?
            """,
            (payload, content_type, now, expires_at, item_id),
        )

    return {"id": item_id}
