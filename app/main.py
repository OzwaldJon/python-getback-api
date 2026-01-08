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
