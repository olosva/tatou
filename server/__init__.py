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
