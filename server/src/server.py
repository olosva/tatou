import os
import io
import base64
import hashlib
import datetime as dt
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, g, send_file, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
import sys, types

# imghdr was removed in Python 3.13 – create a minimal stub if missing
try:
    import imghdr  # is on <=3.12
except Exception:
    if sys.version_info >= (3, 13) and "imghdr" not in sys.modules:
        _im = types.ModuleType("imghdr")

        def what(file, h=None):  # minimali stub
            return None

        _im.what = what
        sys.modules["imghdr"] = _im

# RMAP – keep the app executable even if the package is missing
try:
    from rmap.identity_manager import IdentityManager
    from rmap.rmap import RMAP
except Exception:
    IdentityManager = None
    RMAP = None

import pickle as _std_pickle
import secrets
import uuid
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
    _pickle = _std_pickle

import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod
from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method

active_sessions = {}


# --- Helpers for secure storage format of crypto parameters ---
def _to_b64_if_bytes(x):
    """Returnera Base64-sträng om x är bytes/bytearray/memoryview, annars x."""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(x)).decode("ascii")
    return x


def _from_db_blob_or_b64(x):
    """Konvertera DB-fält (BLOB/bytes/base64-sträng) till rå bytes för crypto."""
    if x is None:
        return None
    if isinstance(x, memoryview):
        x = x.tobytes()
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        # Try base64 decoding, otherwise assume UTF-8
        try:
            return base64.b64decode(x)
        except Exception:
            return x.encode("utf-8", "ignore")
    try:
        return bytes(x)
    except Exception:
        return None


def create_app():
    app = Flask(__name__)

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")
    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # Fix path to keys
    BASE_DIR = Path(__file__).parent.resolve()
    client_keys_dir = BASE_DIR / "pki"
    server_public_key_path = BASE_DIR / "pki" / "Group_20.asc"
    server_private_key_path = BASE_DIR / "server_private_key" / "private_key.asc"
    # TODO: move passfras to ENV in prod
    server_private_key_passphrase = '2e*H*iupUWEL!!%^D2U'

    identity_manager = None
    rmap = None
    if IdentityManager and RMAP:
        identity_manager = IdentityManager(
            client_keys_dir,
            server_public_key_path,
            server_private_key_path,
            server_private_key_passphrase
        )
        rmap = RMAP(identity_manager)

    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        # Test/override
        override = (
            os.environ.get("DB_URL")
            or os.environ.get("DATABASE_URL")
            or os.environ.get("SQLALCHEMY_DATABASE_URI")
        )
        if override:
            return override

        # Default: MySQL in Docker
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
                #extract sessionID from the token
                session_id = data["session_id"]
                 #check that the sessionID is in the active sessions
                if session_id not in active_sessions:
                    return _auth_error("Invalid session (naughty boy?)")
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            #extract user info from the active sessions using the sessionID and set g.user with the info
            user_data = active_sessions[session_id]
            g.user = {"id": user_data["uid"], "login": user_data["login"], "email": user_data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---

    @app.route("/<path:filename>")
    def static_files(filename):
     # List of allowed files (these can be accessed by the public without security risk)
        allowed_files = {
            "documents.html",
            "index.html",
            "login.html",
            "signup.html",
            "style.css",
        }
        if filename not in allowed_files:
            return jsonify({"error": "Access denied"}), 403
        return app.send_static_file(filename) 

    @app.route("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
            return jsonify({"message": "The server is down.", "db_connected": db_ok}), 503
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        #creates a random uid instead of autoincrement to avoid enumeration attacks
        uid = str(uuid.uuid4())

        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400
        # For test: min 3 characters (change in prod)
        if len(password) < 3:
            return jsonify({"error": "password must be at least 8 characters"}), 400
        if "@" not in email:
            return jsonify({"error": "invalid email address"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("INSERT INTO Users (email, hpassword, login, id) VALUES (:email, :hpw, :login, :id)"),
                    {"email": email, "hpw": hpw, "login": login, "id": uid},
                )
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            app.logger.warning(f"Duplicate user: {email} / {login}")
            return jsonify({"error": "invalid input"}), 400
        except Exception as e:
            app.logger.error(f"DB error: {e}")
            return jsonify({"error": "internal server error"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {email, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400
        if "@" not in email:
            return jsonify({"error": "invalid email address"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            app.logger.error(f"DB error: {e}")
            return jsonify({"error": "internal server error"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            app.logger.warning(f"Failed login attempt for: {email}")
            return jsonify({"error": "invalid credentials"}), 401

        #set a session variable instead of a token
        session_id = secrets.token_urlsafe(32)
        #add the session to the active sessions
        active_sessions[session_id] = {"uid": row.id, "login": row.login, "email": row.email}
        
        
        
        #token now contains the same info as before, but with the session id
        #we can then look up the session id in the active sessions to get the user info and compare it to the u.id in the token
        token = _serializer().dumps({"session_id": session_id})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

# --- PDF validation ---
# First: try reading as a real PDF. If pypdf complains, fall back to
# a minimal check that the file starts with "%PDF-".
        try:
            PdfReader(file)
            file.seek(0)  # reset the pointer after reading
        except PdfReadError:
            file.seek(0)  # *important*: go to the beginning before we check the header
            head = file.read(5)
            file.seek(0)
            if not isinstance(head, (bytes, bytearray)) or not head.startswith(b"%PDF-"):
                return jsonify({"error": "invalid PDF file"}), 400
            app.logger.warning("PDF validation fallback: header ok, pypdf failed – accepting upload")
        except Exception:
            file.seek(0)
            head = file.read(5)
            file.seek(0)
            if not isinstance(head, (bytes, bytearray)) or not head.startswith(b"%PDF-"):
                return jsonify({"error": "invalid PDF file"}), 400
            app.logger.warning("PDF validation fallback (generic): header ok – accepting upload")

        fname = file.filename
        #use documentID to avoid directory traversal attacks
        did = str(uuid.uuid4())

        user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name
        file.save(stored_path)

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size, id)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size, :id)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": g.user["id"],
                        "sha256hex": sha_hex,
                        "size": int(size),
                        "id": did,
                    },
                )
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({
            "id": row.id,
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": g.user["id"]},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        docs = [{
            "id": r.id,
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200

    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<string:document_id>")
    @require_auth
    def list_versions(document_id: str | None = None):
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = str(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin AND d.id = :did
                    """),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": str(r.id),
            "documentid": str(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """),
                    #FIXME so that it uses the user id instead of login
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": str(r.id),
            "documentid": str(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    # GET /api/get-document or /api/get-document/<id>  → return PDF inline
    @app.get("/api/get-document")
    @app.get("/api/get-document/<string:document_id>")
    @require_auth
    def get_document(document_id: str | None = None):
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = str(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": g.user["id"]},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503
        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    # GET /api/get-version/<link>  → return wm PDF inline
    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            app.logger.error(f"DB error: {e}")
            return jsonify({"error": "internal server error"}), 503
        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        if not file_path.name.lower().endswith(".pdf"):
            return jsonify({"error": "invalid file type"}), 400

        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp

    # Helper: safely resolve a path under STORAGE_DIR
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document
    @app.route("/api/delete-document", methods=["DELETE", "POST"])
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: str | None = None):
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
        # Fetch the document (enforce ownership)
        #fixed sql injection vulnerability here by using parameterized queries
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT * FROM Documents WHERE id = :id AND ownerid = :uid LIMIT 1"),
                    {"id": doc_id, "uid": g.user["id"]},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
            else:
                file_missing = True
        except RuntimeError as e:
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        try:
            with get_engine().begin() as conn:
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
        except Exception as e:
            return jsonify({"error": f"database error during delete: {str(e)}"}), 503

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,
        }), 200

    #seperate function to allow easier calling from both RMAP and the internal endpoint
    #this way means we can still have the require_auth decorator on the internal endpoint, but still call it as a normal function from RMAP
    def create_internal_watermark(
        uid: str,
        document_id: str | None = None,
        link_token: str | None = None,
        **kwargs #neat keyword :)
    ):
        payload = kwargs
        app.logger.debug("create_internal_watermark called")
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
        
        #if the method gets called from RMAP it might not have a method in the payload so we select the best one as default
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position")
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            doc_id = str(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (str) is required"}), 400
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # lookup the document; enforce ownership
        #checks that the document belongs to the user via ownerID
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": uid},
                ).first()
        except Exception as e:
            app.logger.error("DB error in create_internal_watermark lookup: %s", e)
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # apply watermark with the additional parameters if needed
        try:
            result = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )

            if isinstance(result, (bytes, bytearray)):
                result = {"pdf_bytes": bytes(result)}

            if isinstance(result, dict) and "pdf_bytes" not in result:
                if "bytes" in result:
                    result["pdf_bytes"] = result["bytes"]
                elif "data" in result:
                    result["pdf_bytes"] = result["data"]

            wm_bytes = result["pdf_bytes"]
            iv = result.get("nonce") or result.get("iv")
            tag = result.get("tag")
            salt = result.get("salt")
            secret_out = result.get("secret", secret)

            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            app.logger.error("watermarking failed: %s", e)
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        unique_stamp = dt.datetime.utcnow().strftime("%Y%m%d%H%M%S%f") + "-" + secrets.token_hex(3)
        candidate = f"{base_name}__{intended_slug}__{unique_stamp}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        vid = str(uuid.uuid4())

        
        # If link_token is provided (e.g., RMAP flow), keep it..
        def _new_link_token():
            rnd = secrets.token_hex(8)
            return hashlib.sha1(f"{candidate}:{rnd}".encode("utf-8")).hexdigest()

        if link_token is None:
            link_token = _new_link_token()

        # Insert with small retry loop if link happens to collide
        from sqlalchemy.exc import IntegrityError as SAIntegrityError
        max_tries = 3
        for attempt in range(max_tries):
            try:
                with get_engine().begin() as conn:
                    conn.execute(
                        text("""
                            INSERT INTO Versions (id, documentid, link, intended_for, secret, iv, tag, salt, method, position, path)
                            VALUES (:id, :documentid, :link, :intended_for, :secret, :iv, :tag, :salt, :method, :position, :path)
                        """),
                        {
                            "id": vid,
                            "documentid": doc_id,
                            "link": link_token,
                            "intended_for": intended_for,
                            "secret": secret_out,
                            "iv": iv,
                            "tag": tag,
                            "salt": salt,
                            "method": method,
                            "position": position or "",
                            "path": str(dest_path),
                        },
                    )
                break  # success
            except SAIntegrityError as e:
                # If duplicate link, regenerate and retry
                if "Duplicate entry" in str(e) and "uq_Versions_link" in str(e) and attempt < (max_tries - 1):
                    link_token = _new_link_token()
                    continue
                # cleanup on failure
                try:
                    dest_path.unlink(missing_ok=True)
                except Exception:
                    pass
                return jsonify({"error": f"database error during version insert: {e}"}), 503
            except Exception as e:
                try:
                    dest_path.unlink(missing_ok=True)
                except Exception:
                    pass
                return jsonify({"error": f"database error during version insert: {e}"}), 503

        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201

    # POST /api/create-watermark eller /api/create-watermark/<id>
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<string:document_id>")
    @require_auth
    def create_watermark(document_id: str | None = None):
        payload = request.get_json(silent=True) or {}
        return create_internal_watermark(
            document_id=document_id,
            uid=g.user["id"],
            **payload
        )

    #@app.post("/api/load-plugin")
    #@require_auth
    #def load_plugin():
    #    """
    #    Ladda en serialiserad klass som implementerar WatermarkingMethod från
    #    STORAGE_DIR/files/plugins/<filename>.{pkl|dill} och registrera den i wm_mod.METHODS.
    #    Body: { "filename": "MyMethod.pkl", "overwrite": false }
    #    """
    #    payload = request.get_json(silent=True) or {}
    #    filename = (payload.get("filename") or "").strip()
    #    overwrite = bool(payload.get("overwrite", False))
#
    #    if not filename:
    #        return jsonify({"error": "filename is required"}), 400
#
    #    storage_root = Path(app.config["STORAGE_DIR"])
    #    plugins_dir = storage_root / "files" / "plugins"
    #    try:
    #        plugins_dir.mkdir(parents=True, exist_ok=True)
    #        plugin_path = plugins_dir / filename
    #    except Exception as e:
    #        return jsonify({"error": f"plugin path error: {e}"}), 500
#
    #    if not plugin_path.exists():
    #        return jsonify({"error": f"plugin file not found: {filename}"}), 404
#
    #    try:
    #        with plugin_path.open("rb") as f:
    #            obj = _pickle.load(f)
    #    except Exception as e:
    #        return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400
#
    #    if isinstance(obj, type):
    #        cls = obj
    #    else:
    #        cls = obj.__class__
#
    #    method_name = getattr(cls, "name", getattr(cls, "__name__", None))
    #    if not method_name or not isinstance(method_name, str):
    #        return jsonify({"error": "plugin class must define a readable name (class.__name__ or .name)"}), 400
#
    #    has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
    #    if WatermarkingMethod is not None:
    #        is_ok = issubclass(cls, WatermarkingMethod) and has_api
    #    else:
    #        is_ok = has_api
    #    if not is_ok:
    #        return jsonify({"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}), 400
#
    #    WMUtils.METHODS[method_name] = cls()
#
    #    return jsonify({
    #        "loaded": True,
    #        "filename": filename,
    #        "registered_as": method_name,
    #        "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
    #        "methods_count": len(WMUtils.METHODS)
    #    }), 201

    # GET /api/get-watermarking-methods
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []
        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
        return jsonify({"methods": methods, "count": len(methods)}), 200

    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<string:document_id>")
    @require_auth
    def read_watermark_api(document_id: str | None = None):
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        try:
            doc_id = str(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        # Get the correct version for that particular method
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT v.documentid, v.path, v.method, v.salt, v.tag, v.iv
                        FROM Versions v
                        JOIN Documents d ON v.documentid = d.id
                        WHERE v.documentid = :id
                          AND d.ownerid = :uid
                          AND v.method = :method
                        ORDER BY v.id DESC
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": g.user["id"], "method": method},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Normalize DB values ​​to raw bytes
        iv_b   = _from_db_blob_or_b64(row.iv)
        tag_b  = _from_db_blob_or_b64(row.tag)
        salt_b = _from_db_blob_or_b64(row.salt)

        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key,
                position=position,
                iv=iv_b,
                tag=tag_b,
                salt=salt_b
            )
        except Exception as e:
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400

        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201

   
    @app.post("/api/rmap-initiate")
    #@require_auth
    def initiate_rmap():
        if request.is_json:
            payload = request.get_json(force=True)
        else:
        # Get raw text/binary data
            payload = json.loads(request.get_data(as_text=True))
        if not rmap:
            return jsonify({"error": "RMAP not available on this server"}), 501

        result = rmap.handle_message1(payload)
        #we need to return the entire dict returned by handle_message1 instead of just the payload
        return jsonify(result), 200

    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        if request.is_json:
            payload = request.get_json()
            print(payload.get("payload"))
            print("1020")
        else:
            # Get raw text/binary data
            payload = request.get_data(as_text=True)
            print(payload)
            print("1026")

        if not rmap:
            return jsonify({"error": "RMAP not available on this server"}), 501
        
        # Id to admin document that others can watermark (actual ids for doc and user on the VM)
        admin_uid = 'ae558aec-7162-480f-af24-5f77dda55f92'
        pdf_id = '3baab07c-03f8-49bb-9f24-2e456e74ceb3'
        result = rmap.handle_message2(payload)

        # Creates a watermarked version and reuses the RMAP link
        create_internal_watermark(
            uid=admin_uid,
            document_id=pdf_id,
            link_token=result.get("result"),
            method="wm-encrypted",
            intended_for="rmap_recipient",
            secret="watermarked",
            key="keysecret",
            position="none"
        )
        
        
        #link_url = url_for("get_version", link=result.get("result"), _external=True)
        #print("Generated RMAP link URL:", link_url)
        #use get-version endpoint with the newly created wm pdf in order for the user to get their pdf 
        #instead of returning the correct url in plain text we need to return just the hex
        return jsonify(result), 200

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
