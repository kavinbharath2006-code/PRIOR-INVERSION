import sqlite3, json, time

DB = "bdl_ledger.db"

def init():
    con = sqlite3.connect(DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            did       TEXT PRIMARY KEY,
            cred_hash TEXT NOT NULL,
            status    TEXT NOT NULL DEFAULT 'ACTIVE',
            issued_at REAL,
            expires_at REAL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            event     TEXT,
            did       TEXT,
            timestamp REAL,
            detail    TEXT
        )
    """)
    con.commit()
    con.close()

def anchor(did, cred_hash, ttl_days=365):
    now = time.time()
    con = sqlite3.connect(DB)
    con.execute(
        "INSERT OR REPLACE INTO credentials VALUES (?,?,?,?,?)",
        (did, cred_hash, "ACTIVE", now, now + ttl_days * 86400)
    )
    con.execute(
        "INSERT INTO events(event,did,timestamp,detail) VALUES (?,?,?,?)",
        ("CredentialIssued", did, now, cred_hash)
    )
    con.commit(); con.close()

def revoke(did, reason="suspended"):
    now = time.time()
    con = sqlite3.connect(DB)
    con.execute("UPDATE credentials SET status='REVOKED' WHERE did=?", (did,))
    con.execute(
        "INSERT INTO events(event,did,timestamp,detail) VALUES (?,?,?,?)",
        ("CredentialRevoked", did, now, reason)
    )
    con.commit(); con.close()

def lookup(did):
    con = sqlite3.connect(DB)
    row = con.execute(
        "SELECT cred_hash, status, expires_at FROM credentials WHERE did=?", (did,)
    ).fetchone()
    con.close()
    return row  # (hash, status, expires_at) or None

def log_verification(did, verifier_did, result):
    con = sqlite3.connect(DB)
    con.execute(
        "INSERT INTO events(event,did,timestamp,detail) VALUES (?,?,?,?)",
        ("VerificationLogged", did, time.time(), f"verifier={verifier_did} result={result}")
    )
    con.commit(); con.close()