import os
import tempfile
import pathlib
import sqlite3
import pytest

# =========================================================
# 0) Välj läge beroende på TEST_HTTP_BASE
# =========================================================
TEST_HTTP_BASE = os.getenv("TEST_HTTP_BASE")

if TEST_HTTP_BASE:
    # ---------------------------
    # HTTP-läge (pratar mot servern i Docker / CI)
    # ---------------------------
    import requests

    @pytest.fixture(scope="session")
    def base_url() -> str:
        # ta bort ev. trailing slash så att base_url + path blir rätt
        return TEST_HTTP_BASE.rstrip("/")

    @pytest.fixture
    def client(base_url):
        class _Client:
            def __init__(self):
                self.s = requests.Session()

            def get(self, path: str, **kwargs):
                return self.s.get(base_url + path, **kwargs)

            def post(self, path: str, **kwargs):
                return self.s.post(base_url + path, **kwargs)

            def delete(self, path: str, **kwargs):
                return self.s.delete(base_url + path, **kwargs)

        return _Client()

else:
    # ---------------------------
    # Lokalt läge (ingen extern server). Vi kör Flask lokalt & SQLite.
    # OBS: Detta täcker "create-user" / "login" m.m. utan MySQL.
    # ---------------------------
    TMP_DIR = tempfile.mkdtemp(prefix="tatou_test_")
    DB_PATH = pathlib.Path(TMP_DIR) / "test.sqlite"
    SQLITE_URL = f"sqlite:///{DB_PATH}"
    STORAGE_DIR = pathlib.Path(TMP_DIR) / "storage"
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    # Miljövariabler som server.py läser (din DB-override)
    os.environ.update({
        "TESTING": "1",
        "FLASK_ENV": "testing",
        "DB_URL": SQLITE_URL,           # server.db_url() plockar upp denna
        "STORAGE_DIR": str(STORAGE_DIR),
        # Töm MySQL-relaterat så de inte stör i lokalt läge
        "DB_HOST": "",
        "DB_USER": "",
        "DB_PASSWORD": "",
    })

    # Minimal SQL-schema i SQLite som räcker för auth-flöden m.m.
    _DDL = """
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS Users (
      id        CHAR(36) PRIMARY KEY,
      email     TEXT UNIQUE NOT NULL,
      login     TEXT UNIQUE NOT NULL,
      hpassword TEXT NOT NULL,
      creation  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS Documents (
      id        CHAR(36) PRIMARY KEY,
      name      TEXT NOT NULL,
      path      TEXT NOT NULL,
      ownerid   CHAR(36) NOT NULL,
      sha256    BLOB,
      size      INTEGER,
      creation  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
    _conn = sqlite3.connect(DB_PATH)
    try:
        _conn.executescript(_DDL)
        _conn.commit()
    finally:
        _conn.close()

    # Importera din app-factory och exponera pytest-fixtures
    from server import create_app

    @pytest.fixture(scope="session")
    def app():
        app = create_app()
        app.config.update(TESTING=True)
        return app

    @pytest.fixture
    def client(app):
        return app.test_client()

