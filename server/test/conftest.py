# --- BEGIN robust compat alias for tests that patch "server.src.*" ---
import sys, types, importlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]   # .../server
SRC_DIR   = REPO_ROOT / "src"

# Säkerställ att både repo-roten (för att kunna importera paketet "server")
# och src-katalogen (för moduler under src/) finns på sys.path.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# 1) Importera ALLTID det riktiga paketet "server" från filsystemet.
#    (Vi skapar INTE en dummy. Om importen misslyckas vill vi hellre se ett tydligt fel.)
server_mod = importlib.import_module("server")

# 2) Skapa eller hämta en syntetisk modul 'server.src' och exponera som attribut.
if "server.src" in sys.modules:
    src_alias = sys.modules["server.src"]
else:
    src_alias = types.ModuleType("server.src")
    sys.modules["server.src"] = src_alias
setattr(server_mod, "src", src_alias)

# 3) Binda under-moduler som testerna patchar: 'server.src.wm_encrypted' -> verklig modul.
def _bind(subname: str):
    # Försök först importera direkt (tack vare SRC_DIR på sys.path), annars "src.subname"
    try:
        real = importlib.import_module(subname)
    except ModuleNotFoundError:
        real = importlib.import_module(f"src.{subname}")
    # Registrera både som attribut och i sys.modules med full namnrymd
    setattr(src_alias, subname, real)
    sys.modules[f"server.src.{subname}"] = real

# Lägg till de submoduler som patchas i testerna
for name in ("wm_encrypted",):
    _bind(name)
# --- END robust compat alias ---


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

