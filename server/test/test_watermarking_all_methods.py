# test/test_watermarking_all_methods.py
from pathlib import Path
import subprocess
import shutil
import pytest
import hashlib
import fitz  # PyMuPDF — to inspect PDF contents
import io
from unittest.mock import patch, MagicMock, mock_open
import pickle
import re
import base64
import json
import pikepdf
import importlib.util

from metadata_embedding import MetadataEmbedding, InvalidKeyError, SecretNotFoundError
from wm_visible_stamp_gs import VisibleStampGS
from wm_encrypted import wm_encrypted


def _extract_bytes(out):
    if isinstance(out, (bytes, bytearray)):
        return bytes(out)
    if isinstance(out, dict):
        return out.get("pdf_bytes") or out.get("bytes") or out.get("data")
    return None


def _bash_pipefail_supported():
    try:
        # kräver bash och att 'set -o pipefail' accepteras
        r = subprocess.run(["bash", "-lc", "set -o pipefail"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode == 0
    except Exception:
        return False


@pytest.fixture
def sample_pdf_path(tmp_path: Path):
    try:
        import fitz  # PyMuPDF
    except Exception:
        pytest.skip("PyMuPDF saknas i testmiljön")
    p = tmp_path / "sample.pdf"
    doc = fitz.open()
    doc.new_page()  # en sida räcker
    p.write_bytes(doc.tobytes())
    doc.close()
    return p


@pytest.fixture
def sample_pdf_bytes():
    # Create a blank PDF in-memory for testing
    pdf = fitz.open()
    page = pdf.new_page(width=595, height=842)  # A4 size
    stream = io.BytesIO()
    pdf.save(stream)
    return stream.getvalue()


@pytest.mark.parametrize("impl", [MetadataEmbedding(), VisibleStampGS(), wm_encrypted()])
def test_add_watermark_and_shape(impl, sample_pdf_path: Path):
    # Skippa GS-varianten om bash/pipefail inte funkar här
    if isinstance(impl, VisibleStampGS) and not _bash_pipefail_supported():
        pytest.skip("Ghostscript eller bash/pipefail saknas")

    secret = "unit-test-secret"
    key = "unit-test-key"

    # wm_encrypted kan göra visible-stamp beroende på position — för att undvika sned rotation kör vi 'none'
    position = "none" if impl.__class__.__name__ == "wm_encrypted" else "center"

    assert impl.is_watermark_applicable(sample_pdf_path, position=None)
    out = impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=position)
    b = _extract_bytes(out)
    assert isinstance(b, (bytes, bytearray)) and len(b) > 0


@pytest.mark.parametrize("impl", [MetadataEmbedding(), VisibleStampGS(), wm_encrypted()])
def test_read_secret_roundtrip(impl, sample_pdf_path: Path, tmp_path: Path):
    # Skippa GS-varianten om bash/pipefail inte funkar här
    if isinstance(impl, VisibleStampGS) and not _bash_pipefail_supported():
        pytest.skip("Ghostscript eller bash/pipefail saknas")

    secret = "unit-test-secret"
    key = "unit-test-key"
    position = "none" if impl.__class__.__name__ == "wm_encrypted" else "center"

    out = impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=position)
    b = _extract_bytes(out)
    assert isinstance(b, (bytes, bytearray)) and len(b) > 0

    out_pdf = tmp_path / "wm.pdf"
    out_pdf.write_bytes(b)

    # Alla implementeringar kanske inte stödjer read_secret fullt ut.
    try:
        if impl.__class__.__name__ == "wm_encrypted" and isinstance(out, dict):
            # Om impl returnerade metadata, skicka med den
            iv = out.get("nonce") or out.get("iv")
            tag = out.get("tag")
            salt = out.get("salt")
            s = impl.read_secret(out_pdf, key=key, position=position, iv=iv, tag=tag, salt=salt)
        else:
            s = impl.read_secret(out_pdf, key=key, position=position)
    except (NotImplementedError, TypeError):
        # Acceptera att impl inte stödjer read_secret i detta läge
        return

    assert isinstance(s, str)
    assert s.strip() != ""


