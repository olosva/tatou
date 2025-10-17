# Makes `from server import create_app` work both:
# - Locally (tests import from ./server/src/server.py)
# - In Docker image (imports from src.server)

from pathlib import Path
import importlib.util
import sys

def _load_create_app():
    here = Path(__file__).resolve().parent
    local_src_server = here / "src" / "server.py"

    # Case 1: local test environment – load server/src/server.py directly
    if local_src_server.exists():
        spec = importlib.util.spec_from_file_location(
            "_tatou_server_module", str(local_src_server)
        )
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        sys.modules[spec.name] = module  # make it importable by submodules if needed
        assert spec and spec.loader, "Invalid import spec for local server module"
        spec.loader.exec_module(module)  # type: ignore[call-arg]
        return getattr(module, "create_app")

    # Case 2: docker image – /app/src on PYTHONPATH
    try:
        from src.server import create_app as _create_app  # type: ignore
        return _create_app
    except Exception as e:
        raise ImportError(
            "Could not locate create_app in either local server/src/server.py or src.server"
        ) from e

create_app = _load_create_app()
del _load_create_app

# --- BEGIN compat: expose server.src.wm_encrypted for tests/patch ---
import sys, types, importlib

# Skapa/återanvänd submodulen 'server.src'
_src_mod_name = "server.src"
src_mod = sys.modules.get(_src_mod_name)
if src_mod is None:
    src_mod = types.ModuleType(_src_mod_name)
    sys.modules[_src_mod_name] = src_mod
    # exponera som attribut på paketet 'server'
    setattr(sys.modules[__name__], "src", src_mod)

# Binda 'server.src.wm_encrypted' till den riktiga modulen
try:
    real = importlib.import_module("wm_encrypted")      # fungerar då /app/src finns på PYTHONPATH
except ModuleNotFoundError:
    real = importlib.import_module("src.wm_encrypted")  # fallback

sys.modules["server.src.wm_encrypted"] = real
setattr(src_mod, "wm_encrypted", real)
# --- END compat ---

