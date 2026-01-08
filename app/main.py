import json
import os
import sqlite3
import time
import uuid
import base64
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, HTTPException, Request, Response

TTL_SECONDS = 48 * 60 * 60
KDF_ITERATIONS = int(os.environ.get("KDF_ITERATIONS", "200000"))

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

app = FastAPI(title="GetBack API")


def _now_ts() -> int:
    return int(time.time())


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _get_passphrase(request: Request) -> Optional[str]:
    value = request.headers.get("x-passphrase")
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
                kdf_iterations INTEGER
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_items_expires_at ON items(expires_at)")

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
    passphrase = _get_passphrase(request)

    item_id = str(uuid.uuid4())
    now = _now_ts()
    expires_at = now + TTL_SECONDS

    encrypted = 0
    salt_b64 = None
    nonce_b64 = None
    kdf_iterations = None
    stored_payload = payload

    if passphrase is not None:
        ciphertext_b64, salt_b64, nonce_b64, kdf_iterations = _encrypt(
            payload.encode("utf-8"), passphrase)
        stored_payload = ciphertext_b64
        encrypted = 1

    with _connect() as conn:
        _cleanup_expired(conn)
        conn.execute(
            """
            INSERT INTO items(
              id, payload, content_type, created_at, updated_at, expires_at,
              encrypted, salt_b64, nonce_b64, kdf_iterations
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (item_id, stored_payload, content_type, now, now,
             expires_at, encrypted, salt_b64, nonce_b64, kdf_iterations),
        )

    return {"id": item_id}


def _get_item(conn: sqlite3.Connection, item_id: str) -> Optional[sqlite3.Row]:
    _cleanup_expired(conn)
    row = conn.execute(
        """
        SELECT id, payload, content_type, expires_at,
               encrypted, salt_b64, nonce_b64, kdf_iterations
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
        passphrase = _get_passphrase(request)
        if passphrase is None:
            raise HTTPException(status_code=404, detail="Not found")
        try:
            plaintext = _decrypt(
                row["payload"],
                passphrase,
                row["salt_b64"],
                row["nonce_b64"],
                int(row["kdf_iterations"] or KDF_ITERATIONS),
            )
        except Exception as exc:
            raise HTTPException(status_code=404, detail="Not found") from exc

        return Response(content=plaintext, media_type=row["content_type"])

    return Response(content=row["payload"], media_type=row["content_type"])


@app.post("/{item_id}")
async def update_item(item_id: str, request: Request):
    raw = await request.body()
    payload, content_type = _normalize_payload(request, raw)
    passphrase = _get_passphrase(request)

    now = _now_ts()
    expires_at = now + TTL_SECONDS

    with _connect() as conn:
        row = _get_item(conn, item_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Not found")

        if int(row["encrypted"] or 0) == 1:
            if passphrase is None:
                raise HTTPException(status_code=404, detail="Not found")
            try:
                _decrypt(
                    row["payload"],
                    passphrase,
                    row["salt_b64"],
                    row["nonce_b64"],
                    int(row["kdf_iterations"] or KDF_ITERATIONS),
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=404, detail="Not found") from exc

            ciphertext_b64, salt_b64, nonce_b64, kdf_iterations = _encrypt(
                payload.encode("utf-8"), passphrase)
            conn.execute(
                """
                UPDATE items
                SET payload = ?, content_type = ?, updated_at = ?, expires_at = ?,
                    encrypted = 1, salt_b64 = ?, nonce_b64 = ?, kdf_iterations = ?
                WHERE id = ?
                """,
                (ciphertext_b64, content_type, now, expires_at,
                 salt_b64, nonce_b64, kdf_iterations, item_id),
            )
            return {"id": item_id}

        if passphrase is not None:
            ciphertext_b64, salt_b64, nonce_b64, kdf_iterations = _encrypt(
                payload.encode("utf-8"), passphrase)
            conn.execute(
                """
                UPDATE items
                SET payload = ?, content_type = ?, updated_at = ?, expires_at = ?,
                    encrypted = 1, salt_b64 = ?, nonce_b64 = ?, kdf_iterations = ?
                WHERE id = ?
                """,
                (ciphertext_b64, content_type, now, expires_at,
                 salt_b64, nonce_b64, kdf_iterations, item_id),
            )
            return {"id": item_id}

        conn.execute(
            """
            UPDATE items
            SET payload = ?, content_type = ?, updated_at = ?, expires_at = ?,
                encrypted = 0, salt_b64 = NULL, nonce_b64 = NULL, kdf_iterations = NULL
            WHERE id = ?
            """,
            (payload, content_type, now, expires_at, item_id),
        )

    return {"id": item_id}
