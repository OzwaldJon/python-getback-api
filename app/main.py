import json
import os
import sqlite3
import time
import uuid
from typing import Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, Response

TTL_SECONDS = 48 * 60 * 60

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

app = FastAPI(title="GetBack API")


def _now_ts() -> int:
    return int(time.time())


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


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
                expires_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_items_expires_at ON items(expires_at)")


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


@app.post("/")
async def create_item(request: Request):
    raw = await request.body()
    payload, content_type = _normalize_payload(request, raw)

    item_id = str(uuid.uuid4())
    now = _now_ts()
    expires_at = now + TTL_SECONDS

    with _connect() as conn:
        _cleanup_expired(conn)
        conn.execute(
            "INSERT INTO items(id, payload, content_type, created_at, updated_at, expires_at) VALUES(?,?,?,?,?,?)",
            (item_id, payload, content_type, now, now, expires_at),
        )

    return {"id": item_id}


def _get_item(conn: sqlite3.Connection, item_id: str) -> Optional[sqlite3.Row]:
    _cleanup_expired(conn)
    row = conn.execute(
        "SELECT id, payload, content_type, expires_at FROM items WHERE id = ?",
        (item_id,),
    ).fetchone()
    return row


@app.get("/{item_id}")
def read_item(item_id: str):
    with _connect() as conn:
        row = _get_item(conn, item_id)

    if row is None:
        raise HTTPException(status_code=404, detail="Not found")

    return Response(content=row["payload"], media_type=row["content_type"])


@app.post("/{item_id}")
async def update_item(item_id: str, request: Request):
    raw = await request.body()
    payload, content_type = _normalize_payload(request, raw)

    now = _now_ts()
    expires_at = now + TTL_SECONDS

    with _connect() as conn:
        row = _get_item(conn, item_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Not found")

        conn.execute(
            "UPDATE items SET payload = ?, content_type = ?, updated_at = ?, expires_at = ? WHERE id = ?",
            (payload, content_type, now, expires_at, item_id),
        )

    return {"id": item_id}
