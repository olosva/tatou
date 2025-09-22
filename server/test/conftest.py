import os, tempfile, pathlib
import pytest

# 1) Skapa en temporär SQLite-databas för tester
TMP_DIR = tempfile.mkdtemp(prefix="tatou_test_")
DB_PATH = pathlib.Path(TMP_DIR) / "test.sqlite"
SQLITE_URL = f"sqlite:///{DB_PATH}"

# 2) Överstyr vanliga env-nycklar INNAN appen importeras
os.environ.update({
    "TESTING": "1",
    "FLASK_ENV": "testing",
    # Vanliga nycklar som projekt brukar läsa:
    "SQLALCHEMY_DATABASE_URI": SQLITE_URL,
    "DATABASE_URL": SQLITE_URL,
    "DB_URL": SQLITE_URL,
    "DB_URI": SQLITE_URL,
    "DB_DSN": SQLITE_URL,
    # Töm host-variabler så inget pekar på 'db'
    "DB_HOST": "",
    "MYSQL_HOST": "",
})

# 3) Importera app-factoryn från server/src/server.py (modulnamn = "server")
from server import create_app

@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True)

    # 4) Skapa tabeller oavsett om du kör Flask-SQLAlchemy eller ren SQLAlchemy
    try:
        # Flask-SQLAlchemy-stil
        from server import db
        with app.app_context():
            db.create_all()
    except Exception:
        try:
            # Ren SQLAlchemy-stil
            from server.models import Base  # ändra om din Base ligger annorlunda
            from server import engine
            Base.metadata.create_all(bind=engine)
        except Exception:
            pass

    return app
