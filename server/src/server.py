import os
import io
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
try:
    import imghdr  # finns på <=3.12
except Exception:
    if sys.version_info >= (3, 13) and "imghdr" not in sys.modules:
        _im = types.ModuleType("imghdr")
        def what(file, h=None):  # minimalistisk stub
            return None
        _im.what = what
        sys.modules["imghdr"] = _im
        
try:
    from rmap.identity_manager import IdentityManager
    from rmap.rmap import RMAP
except Exception as _e:
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
    
    #fixa path till keys
    BASE_DIR = Path(__file__).parent.resolve()

    client_keys_dir = BASE_DIR / "pki"
    server_public_key_path = BASE_DIR / "pki" / "Group_20.asc"
    server_private_key_path = BASE_DIR / "server_private_key" / "private_key.asc"
    #remove passphrase from git
    server_private_key_passphrase = '2e*H*iupUWEL!!%^D2U'
    
    #client_keys_dir = 'pki/'
    #server_public_key_path = 'pki/Group_20.asc'
    #server_private_key_path = 'server_private_key/private_key.asc'
    #server_private_key_passphrase = '2e*H*iupUWEL!!%^D2U'
    #
    identity_manager = IdentityManager(client_keys_dir,
     server_public_key_path, 
     server_private_key_path,
     server_private_key_passphrase)

    rmap = RMAP(identity_manager)


    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
    # Test/override: om någon av dessa env-variabler finns, använd den
        override = (
            os.environ.get("DB_URL")
            or os.environ.get("DATABASE_URL")
            or os.environ.get("SQLALCHEMY_DATABASE_URI")
        )
        if override:
            return override

    # Standard: MySQL i Docker
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
            #print(auth)
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
                #print(data)
                #print("rad 76")
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
            
            
            #print("kommer hit verkar bra1")
            return f(*args, **kwargs)
        #print("kommer hit verkar bra2")
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
        #print(email, login, password)
        if not email or not login or not password:
            #print("det är här det fuckar1")
            return jsonify({"error": "email, login, and password are required"}), 400
        #change password for easier testing CHANGE BEFORE PRODUCTION
        if len(password) < 3:
            #print("det är här det fuckar2")
            return jsonify({"error": "password must be at least 8 characters"}), 400
        if "@" not in email:
            #print("det är här det fuckar3")
            return jsonify({"error": "invalid email address"}), 400

        hpw = generate_password_hash(password)

        # SQLAlchemy takes care to protect against SQL injection using parameterized queries
        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login, id) VALUES (:email, :hpw, :login, :id)"),
                    {"email": email, "hpw": hpw, "login": login, "id": uid},
                )
                #uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            print("det är här det fuckar4")
            app.logger.warning(f"Duplicate user: {email} / {login}")
            return jsonify({"error": "invalid input"}), 400
        except Exception as e:
            print("det är här det fuckar5")
            app.logger.error(f"DB error: {e}")
            return jsonify({"error": "internal server error"}), 503
        #print(row.id + " " + row.email + " " + row.login + "178")
        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
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
        
        for keys,values in active_sessions.items():
            print(keys)
            print(values)
        
        #token now contains the same info as before, but with the session id
        #we can then look up the session id in the active sessions to get the user info and compare it to the u.id in the token
        token = _serializer().dumps({"session_id": session_id})
        #print(token)
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200
        #print(row.id, row.login, row.email)
        #the same toke is generated for all users every time they log in
        
        #token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        #print(token)
        #return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # When user uploads document, do we want to give it a new name? Otherwise that name will
    # form the foundation of the secret link (which currently is just the sha1 of the name).
    # Somehow, we need to ensure that the link returned by create_watermark is not easily    # deducible.
    #POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400
        #check that the file is a PDF
        try:
            pdf = PdfReader(file)
            file.seek(0)  # reset file pointer after reading TACK CLAUDE
        except PdfReadError:
            return jsonify({"error": "invalid PDF file"}), 400
        
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
                #print(final_name + " " + str(stored_path) + " " + str(g.user["id"]) + " " + sha_hex + " " + str(size) + " " + did)
                #did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            #print(e)
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
            #print(int(g.user["id"]))
            #print("kommer hit")
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
    
    #GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<string:document_id>")
    @require_auth
    def list_versions(document_id: str | None = None):
        # Support both path param and ?id=/ ?documentid=
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
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<string:document_id>")
    @require_auth
    def get_document(document_id: str | None = None):
        
        #print(document_id)
        #print("kommer hit")
        # Support both path param and ?id=/ ?documentid=
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

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp
    
    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
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

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        if not file_path.name.lower().endswith(".pdf"):
            return jsonify({"error": "invalid file type"}), 400

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp
    
    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: str | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        #print(document_id)
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
                print("här det fuckar")
                row = conn.execute(
                    text("SELECT * FROM Documents WHERE id =  :id AND ownerid = :uid LIMIT 1"),
                    {"id": doc_id, "uid": g.user["id"]},
                ).one()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            # Don’t reveal others’ docs—just say not found
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
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
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                # If your schema does NOT have ON DELETE CASCADE on Version.documentid,
                # uncomment the next line first:
                # conn.execute(text("DELETE FROM Version WHERE documentid = :id"), {"id": doc_id})
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
        except Exception as e:
            return jsonify({"error": f"database error during delete: {str(e)}"}), 503

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,   # null/omitted if everything was fine
        }), 200
        
    #seperate function to allow easier calling from both RMAP and the internal endpoint
    #this way means we can still have the require_auth decorator on the internal endpoint, but still call it as a normal function from RMAP
    def create_internal_watermark(uid: str,
                                  document_id: str | None = None,
                                  link_token: str | None = None,
                                  **kwargs #neat keyword :)
                                  ):
        payload = kwargs
        print("kommer hit med rmap-get-link")
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            print("644")
            return jsonify({"error": "document id required"}), 400

        #payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        #if the method gets called from RMAP it might not have a method in the payload so we select the best one as default
        
        method = payload.get("method")   
        #having a really hard time figuring out how to get the parameters required for the watermarking from RMAP without i looking like shit
        intended_for = payload.get("intended_for")
        position = payload.get("position")
        secret = payload.get("secret")
        key = payload.get("key")
         # validate input
        try:
            doc_id = str(doc_id)
        except (TypeError, ValueError):
            print("661")
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            print("664")
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # lookup the document; enforce ownership
        #checks that the document belongs to the user via ownerID
        print("669")
        print(doc_id)
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
            print("e1", e)
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            print("687")
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
            print("699")
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            print("701")
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            #print("kommer hit 673")
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            print("716")
            print(e)
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # apply watermark → bytes
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
            iv = result.get("nonce")
            tag = result.get("tag")
            salt = result.get("salt")
            secret = result.get("secret")

            #print("kommer hit 703")
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                print("e2")
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            print("e3", e)
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            print("e4")
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500
        
        vid = str(uuid.uuid4())
        
        #check if link_token is provided in the payload via RMAP else do as normal
        if link_token is None:
            link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()
        #print(doc_id, link_token, intended_for, secret, method, position, dest_path)
        #print(link_token)
        #print(uid,document_id , "767")
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
                        "secret": secret,
                        "iv": iv,
                        "tag": tag,
                        "salt": salt,
                        "method": method,
                        "position": position or "",
                        "path": dest_path
                    },
                )
                # vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            print("746")
            print(e)
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
    
        
       
       
         
    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<string:document_id>")
    @require_auth #ändrade till str
    def create_watermark(document_id: str | None = None):
        #''', link_token: str | None = None'''
        payload = request.get_json(silent=True) or {}
        return create_internal_watermark(
            document_id=document_id,
            uid = g.user["id"],
            **payload
        )
        
        
    @app.post("/api/load-plugin")
    @require_auth
    def load_plugin():
        """
        Load a serialized Python class implementing WatermarkingMethod from
        STORAGE_DIR/files/plugins/<filename>.{pkl|dill} and register it in wm_mod.METHODS.
        Body: { "filename": "MyMethod.pkl", "overwrite": false }
        """
        payload = request.get_json(silent=True) or {}
        filename = (payload.get("filename") or "").strip()
        overwrite = bool(payload.get("overwrite", False))

        if not filename:
            return jsonify({"error": "filename is required"}), 400

        # Locate the plugin in /storage/files/plugins (relative to STORAGE_DIR)
        storage_root = Path(app.config["STORAGE_DIR"])
        plugins_dir = storage_root / "files" / "plugins"
        try:
            plugins_dir.mkdir(parents=True, exist_ok=True)
            plugin_path = plugins_dir / filename
        except Exception as e:
            return jsonify({"error": f"plugin path error: {e}"}), 500

        if not plugin_path.exists():
            return jsonify({"error": f"plugin file not found: {safe}"}), 404

        # Unpickle the object (dill if available; else std pickle)
        try:
            with plugin_path.open("rb") as f:
                obj = _pickle.load(f)
        except Exception as e:
            return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400

        # Accept: class object, or instance (we'll promote instance to its class)
        if isinstance(obj, type):
            cls = obj
        else:
            cls = obj.__class__

        # Determine method name for registry
        method_name = getattr(cls, "name", getattr(cls, "__name__", None))
        if not method_name or not isinstance(method_name, str):
            return jsonify({"error": "plugin class must define a readable name (class.__name__ or .name)"}), 400

        # Validate interface: either subclass of WatermarkingMethod or duck-typing
        has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
        if WatermarkingMethod is not None:
            is_ok = issubclass(cls, WatermarkingMethod) and has_api
        else:
            is_ok = has_api
        if not is_ok:
            return jsonify({"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}), 400

        # Register the class (not an instance) so you can instantiate as needed later
        WMUtils.METHODS[method_name] = cls()

        return jsonify({
            "loaded": True,
            "filename": filename,
            "registered_as": method_name,
            "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
            "methods_count": len(WMUtils.METHODS)
        }), 201

    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
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
    def read_watermark(document_id: str | None = None):
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
        # allow a couple of aliases for convenience
        
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            doc_id = str(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        # lookup the document; FIXME enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT v.documentid, v.path, v.method, v.salt, v.tag, v.iv
                        FROM Versions v
                        JOIN Documents d ON v.documentid = d.id
                        WHERE v.documentid = :id AND d.ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": g.user["id"]},
                ).first()
        except Exception as e:
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

        #get the parameters from the document needed to read the watermark

        secret = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key,
                position=position,
                iv=row.iv,
                tag=row.tag,
                salt=row.salt
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
        # Get raw POST data
        
        #print(payload)
        if request.is_json: 
            payload = request.get_json()
            print(payload)
        else:
        # Get raw text/binary data
            payload = request.get_data(as_text=True)
            
            
        result = rmap.handle_message1(payload)
        print(result)
        
        return jsonify(result.get("payload")), 200
    
    
    @app.post("/api/rmap-get-link")
    #@require_auth
    def rmap_get_link():
        # Get raw POST data
        
        #print(payload)
        if request.is_json: 
            payload = request.get_json()
            #print(payload)
        else:
        # Get raw text/binary data
            payload = request.get_data(as_text=True)
            
        #id to the pdf on admin@admin.admin account that other groups can watermark    
        admin_uid = '281b4cb1-abdb-4a61-ad33-9a78cbab12b7'
        pdf_id = '619f9c58-6e40-40d2-ae59-07929e8de44b'
        result = rmap.handle_message2(payload)
        
        #we can now create the watermark with the parameters received from RMAP
        create_internal_watermark(
                         uid=admin_uid,
                         document_id=pdf_id,
                         link_token=result.get("result"),
                         method="wm-encrypted",
                         intended_for="rmap_recipient",
                         secret="watermarked",
                         key="keysecret",
                         position = "none")
        
        
        #use get-version endpoint with the newly created wm pdf in order
        #for the user to get their pdf 
        #link = {'http://127.0.0.1:5000/api/get-version/'+result.get("result")}
        #return jsonify({"link" : link}), 200
        link_url = url_for("get_version", link=result.get("result"), _external=True)
        return jsonify({"link": link_url}), 200

    
    return app
    
# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

