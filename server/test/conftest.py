import os
import tempfile
import pathlib
import sqlite3
import pytest

# === 0) Integration-läge via HTTP? ==========================
# Sätt TEST_HTTP_BASE om du vill köra tester mot en redan körande server via HTTP.
# Då gör conftest ingenting (inga imports av appen).
TEST_HTTP_BASE = os.getenv("TEST_HTTP_BASE")
if TEST_HTTP_BASE:
    # Inga fixtures behövs i HTTP-läge
    pass
else:
    # === 1) Lokalt app-läge med SQLite ======================
    TMP_DIR = tempfile.mkdtemp(prefix="tatou_test_")
    DB_PATH = pathlib.Path(TMP_DIR) / "test.sqlite"
    SQLITE_URL = f"sqlite:///{DB_PATH}"
    STORAGE_DIR = pathlib.Path(TMP_DIR) / "storage"
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    # 2) Miljövariabler som din app faktiskt läser
    os.environ.update({
        "TESTING": "1",
        "FLASK_ENV": "testing",
        "DB_URL": SQLITE_URL,     # <-- server.py Steg 1 gör denna aktiv
        "STORAGE_DIR": str(STORAGE_DIR),
        # Töm MySQL-relaterat så de inte stör
        "DB_HOST": "",
        "DB_USER": "",
        "DB_PASSWORD": "",
    })

    # 3) Skapa minimal schema i SQLite (matchar dina tabeller tillräckligt för tester)
    _DDL = """
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS Users (
      id       CHAR(36) PRIMARY KEY,
      email    TEXT UNIQUE NOT NULL,
      login    TEXT UNIQUE NOT NULL,
      hpassword TEXT NOT NULL,
      creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS Documents (
      id       CHAR(36) PRIMARY KEY,
      name     TEXT NOT NULL,
      path     TEXT NOT NULL,
      ownerid  CHAR(36) NOT NULL,
      sha256   BLOB,
      size     INTEGER,
      creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(ownerid) REFERENCES Users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS Versions (
      id           CHAR(36) PRIMARY KEY,
      documentid   CHAR(36) NOT NULL,
      link         CHAR(40) UNIQUE NOT NULL,
      intended_for TEXT NOT NULL,
      secret       TEXT,
      iv           BLOB,
      tag          BLOB,
      salt         BLOB,
      method       TEXT NOT NULL,
      position     TEXT,
      path         TEXT NOT NULL,
      creation     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(documentid) REFERENCES Documents(id) ON DELETE CASCADE
    );
    """
    # Kör DDL en gång
    _conn = sqlite3.connect(DB_PATH)
    try:
        _conn.executescript(_DDL)
        _conn.commit()
    finally:
        _conn.close()

    # 4) Importera app-factoryn
    #  – tack vare Steg 2 kan vi skriva:
    from server import create_app

    @pytest.fixture
    def app():
        app = create_app()
        app.config.update(TESTING=True)
        return app

    @pytest.fixture
    def client(app):
        return app.test_client()
