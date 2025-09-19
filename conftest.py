import os, tempfile, pathlib
import pytest

# Create a temp SQLite DB for this test session
TMP_DIR = tempfile.mkdtemp(prefix="tatou_test_")
DB_PATH = pathlib.Path(TMP_DIR) / "test.sqlite"
SQLITE_URL = f"sqlite:///{DB_PATH}"

# Force DB settings BEFORE importing the app
os.environ.update({
    "TESTING": "1",
    "FLASK_ENV": "testing",
    # Common keys apps read; set a consistent SQLite URL:
    "SQLALCHEMY_DATABASE_URI": SQLITE_URL,
    "DATABASE_URL": SQLITE_URL,
    "DB_URL": SQLITE_URL,
    "DB_URI": SQLITE_URL,
    "DB_DSN": SQLITE_URL,
    # Clear host-based MySQL config so nothing falls back to localhost
    "DB_HOST": "",
    "MYSQL_HOST": "",
})

from server import create_app  # thanks to pytest.ini pythonpath=server/src

@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True)

    # Try to create tables regardless of ORM style
    try:
        from server import db
        with app.app_context():
            db.create_all()
    except Exception:
        try:
            from server.models import Base  # adjust if different
            from server import engine
            Base.metadata.create_all(bind=engine)
        except Exception:
            pass

    return app
