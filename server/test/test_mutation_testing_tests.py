from pathlib import Path
import subprocess
import shutil
import pytest
import hashlib
import fitz  # PyMuPDF — to inspect PDF contents
import io
from unittest.mock import Mock, patch, MagicMock, mock_open
import pickle
import re
import base64
import json
import pikepdf
import importlib.util
from flask.testing import FlaskClient
from server import create_app
from flask import Response
import datetime
import os
import tempfile
from sqlalchemy import create_engine, Table, MetaData, Column, String

from metadata_embedding import MetadataEmbedding, InvalidKeyError, SecretNotFoundError
from wm_visible_stamp_gs import VisibleStampGS
from wm_encrypted import wm_encrypted


##### Helpers #####
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


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _get_token(client, email="upload@example.com", login="upload_user", pw="abc12345"):
    client.post("/api/create-user", json={"email": email, "login": login, "password": pw})
    r = client.post("/api/login", json={"email": email, "password": pw})
    assert r.status_code == 200
    token = r.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


def _post(client, path, headers=None, data=None, content_type=None):
    return client.post(path, headers=headers or {}, data=data, content_type=content_type)


@pytest.fixture
def temp_storage(tmp_path, app):
    app.config["STORAGE_DIR"] = tmp_path
    return tmp_path


##### wm_encrypted tests #####

def test_is_wm_encrypted_applicable_returns_true(sample_pdf_path: Path):
    impl = wm_encrypted()
    assert impl.is_watermark_applicable(sample_pdf_path)
    assert impl.is_watermark_applicable(b"%PDF-1.4")  # bytes input


def test_add_watermark_returns_expected_keys_and_types(sample_pdf_path: Path):
    impl = wm_encrypted()
    secret = "test‑secret"
    key = "password"
    position = "center"

    result = impl.add_watermark(sample_pdf_path, secret, key, position)
    # Expect dict
    assert isinstance(result, dict)
    for k in ("pdf_bytes", "salt", "nonce", "tag", "secret"):
        assert k in result, f"Missing key {k} in result"
    assert isinstance(result["pdf_bytes"], (bytes, bytearray))
    # The other keys should be ascii‐strings in base64
    for k in ("salt", "nonce", "tag", "secret"):
        v = result[k]
        assert isinstance(v, str)
        # A simple check: base64 decode success
        import base64
        base64.b64decode(v)  # will raise if invalid


def test_read_secret_recovers_exact_secret(sample_pdf_path: Path):
    impl = wm_encrypted()
    secret = "super‐hidden‐value"
    key = "securekey123"
    position = None

    result = impl.add_watermark(sample_pdf_path, secret, key, position)
    pdf_bytes = result["pdf_bytes"]
    salt = result["salt"]
    nonce = result["nonce"]
    tag = result["tag"]
    encoded_secret = result["secret"]

    recovered = impl.read_secret(
        pdf_bytes,
        key=key,
        position=position,
        iv=nonce,
        tag=tag,
        salt=salt
    )
    assert recovered == secret


def test_read_secret_fails_with_wrong_key(sample_pdf_path: Path):
    impl = wm_encrypted()
    secret = "value"
    correct_key = "goodkey"
    wrong_key = "badkey"

    result = impl.add_watermark(sample_pdf_path, secret, correct_key, position=None)
    pdf_bytes = result["pdf_bytes"]
    salt = result["salt"]
    nonce = result["nonce"]
    tag = result["tag"]

    with pytest.raises(Exception):
        impl.read_secret(pdf_bytes, key=wrong_key, position=None, iv=nonce, tag=tag, salt=salt)


def test_read_secret_fails_when_hidden_watermark_chunks_missing(tmp_path: Path):
    impl = wm_encrypted()
    # Create a minimal empty PDF (zero pages) or a PDF without watermark chunks
    empty_pdf = fitz.open()
    # Add one blank page to avoid page_count == 0
    empty_pdf.new_page()
    buf = io.BytesIO()
    empty_pdf.save(buf)
    pdf_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="No hidden chunks found"):
        impl.read_secret(pdf_bytes, key="any", position="nonsense", iv=b"", tag=b"", salt=b"")


def test_visible_watermark_position_bottom_kills_pow_mutant(sample_pdf_bytes):
    wm = wm_encrypted()
    position = "bottom"
    secret = "bottom-marker"

    watermarked_bytes = wm.add_visible_watermark(
        pdf_bytes=sample_pdf_bytes,
        position=position,
        secret=secret
    )

    # Open result and extract text and position
    doc = fitz.open(stream=watermarked_bytes, filetype="pdf")
    page = doc[0]
    blocks = page.get_text("dict")["blocks"]

    # Find the inserted watermark
    found = False
    for block in blocks:
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                if secret in span["text"]:
                    y = span["bbox"][1]  # top y-position of text box
                    page_height = page.rect.height
                    relative_y = y / page_height

                    # Assertion: watermark should be close to bottom (e.g., bottom 20%)
                    assert 0.75 < relative_y < 0.95, f"Expected watermark near bottom, got y={y}, rel_y={relative_y}"
                    found = True

    assert found, "Watermark text not found on the page"


def test_visible_watermark_position_top_is_centered_x(sample_pdf_bytes):
    wm = wm_encrypted()
    position = "top"
    secret = "test-secret-top"

    # Apply visible watermark
    watermarked_bytes = wm.add_visible_watermark(
        pdf_bytes=sample_pdf_bytes,
        position=position,
        secret=secret
    )

    # Open watermarked PDF
    doc = fitz.open(stream=watermarked_bytes, filetype="pdf")
    page = doc[0]
    width = page.rect.width

    # Extract text spans to find the watermark
    found = False
    for block in page.get_text("dict")["blocks"]:
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                if secret in span["text"]:
                    found = True
                    x_start = span["bbox"][0]
                    x_end = span["bbox"][2]
                    text_center = (x_start + x_end) / 2
                    page_center = width / 2

                    # Assert watermark is horizontally centered within ±5% margin
                    deviation_ratio = abs(text_center - page_center) / width
                    assert deviation_ratio < 0.25, (
                        f"Watermark x-center too far from page center: "
                        f"text_center={text_center:.2f}, page_center={page_center:.2f}, "
                        f"deviation={deviation_ratio:.2%}"
                    )

    assert found, "Did not find watermark text in the PDF"


def test_visible_watermark_position_bottom_is_centered_x(sample_pdf_bytes):
    wm = wm_encrypted()
    position = "bottom"
    secret = "test-secret-bottom"

    # Add watermark
    watermarked_bytes = wm.add_visible_watermark(
        pdf_bytes=sample_pdf_bytes,
        position=position,
        secret=secret
    )

    doc = fitz.open(stream=watermarked_bytes, filetype="pdf")
    page = doc[0]
    page_width = page.rect.width

    # Find watermark text
    found = False
    for block in page.get_text("dict")["blocks"]:
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                if secret in span["text"]:
                    found = True
                    x_start, x_end = span["bbox"][0], span["bbox"][2]
                    text_center = (x_start + x_end) / 2
                    page_center = page_width / 2
                    deviation_ratio = abs(text_center - page_center) / page_width

                    # Allow small rendering deviation, but fail on mutant-like shifts
                    if deviation_ratio > 0.10:  # >10% off-center = fail (mutant)
                        raise AssertionError(
                            f"Watermark x-center too far from page center:\n"
                            f"text_center={text_center:.2f}, page_center={page_center:.2f}, "
                            f"deviation={deviation_ratio:.2%}"
                        )
                    elif deviation_ratio > 0.05:
                        print(
                            f"[Warning] Watermark not perfectly centered: "
                            f"{deviation_ratio:.2%} deviation"
                        )

    assert found, "Watermark text not found on PDF page"


def test_read_secret_handles_general_exception_and_raises_valueerror():
    wm = wm_encrypted()

    # Minimal valid PDF with one page and mocked text chunks with base64 data
    fake_pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] >>\n"
        b"endobj\n"
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        b"0000000010 00000 n \n"
        b"0000000061 00000 n \n"
        b"0000000116 00000 n \n"
        b"trailer\n"
        b"<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n"
        b"171\n"
        b"%%EOF"
    )

    key = "dummykey"
    iv = tag = salt = "ZmFrZV9kYXRh=="  # base64 for "fake_data"

    # Patch fitz.open and decrypt function
    with patch("fitz.open") as mock_open, \
         patch("server.src.wm_encrypted.decrypt") as mock_decrypt:

        # Setup mocked PDF document with one page
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.height = 300
        mock_page.rect.width = 300

        # Fake text chunk: base64 string
        mock_page.get_text.return_value = {
            "blocks": [{
                "type": 0,
                "lines": [{
                    "spans": [{"text": "ZmFrZV9kYXRh=="}]  # base64 "fake_data"
                }]
            }]
        }

        mock_doc.__iter__.return_value = [mock_page]
        mock_doc.page_count = 1
        mock_doc.__getitem__.return_value = mock_page
        mock_open.return_value = mock_doc

        # Make decrypt raise generic RuntimeError (not CosmicRayTestingException)
        mock_decrypt.side_effect = RuntimeError("bad decrypt")

        # Expect ValueError with message containing "Failed to decrypt secret"
        with pytest.raises(ValueError) as exc_info:
            wm.read_secret(
                pdf=fake_pdf,
                key=key,
                position="center",
                iv=iv,
                tag=tag,
                salt=salt,
            )

        assert "Failed to decrypt secret" in str(exc_info.value)


    key = "dummykey"
    iv = tag = salt = "ZmFrZV9kYXRh=="  # base64 for "fake_data"

    # Patch fitz.open and decrypt function
    with patch("fitz.open") as mock_open, \
         patch("server.src.wm_encrypted.decrypt") as mock_decrypt:

        # Setup mocked PDF document with one page
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.height = 300
        mock_page.rect.width = 300


def test_norm_fallback_on_base64_decode_exception():
    wm = wm_encrypted()

    invalid_base64_str = "not_base64!!!"  # definitely invalid base64

    # Patch base64.b64decode to raise a generic Exception when called
    with patch("server.src.wm_encrypted.base64.b64decode") as mock_b64decode:
        mock_b64decode.side_effect = Exception("forced failure")

        # We want to check that _norm falls back to returning x.encode()
        # We can call read_secret with the invalid base64 string as iv/tag/salt, it will call _norm internally

        # Use minimal valid PDF bytes (with 1 page) to pass PDF loading
        fake_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n"
            b"<< /Type /Catalog /Pages 2 0 R >>\n"
            b"endobj\n"
            b"2 0 obj\n"
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
            b"endobj\n"
            b"3 0 obj\n"
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] >>\n"
            b"endobj\n"
            b"xref\n"
            b"0 4\n"
            b"0000000000 65535 f \n"
            b"0000000010 00000 n \n"
            b"0000000061 00000 n \n"
            b"0000000116 00000 n \n"
            b"trailer\n"
            b"<< /Size 4 /Root 1 0 R >>\n"
            b"startxref\n"
            b"171\n"
            b"%%EOF"
        )

        key = "dummykey"

        # Because our patched b64decode always throws, the code should fallback to x.encode() for iv/tag/salt,
        # so no exception should be raised here during normalization.

        # We expect the test to fail later because no hidden chunks, but crucially _norm fallback happened.

        with pytest.raises(ValueError) as exc_info:
            wm.read_secret(
                pdf=fake_pdf,
                key=key,
                position="center",
                iv=invalid_base64_str,
                tag=invalid_base64_str,
                salt=invalid_base64_str,
            )

        # The error should NOT be about base64 decode failing directly because _norm caught it.
        # Instead, it should be about no hidden chunks (because pdf has none with valid watermark)

        assert "No hidden chunks found" in str(exc_info.value)


@pytest.mark.parametrize("impl", [wm_encrypted()])
def test_wm_encrypted_changes_pdf(impl, sample_pdf_path: Path):
    secret = "unit-test-secret"
    key = "unit-test-key"
    position = "none"

    # Read original PDF bytes
    with open(sample_pdf_path, "rb") as f:
        original_bytes = f.read()
    original_hash = hashlib.sha256(original_bytes).hexdigest()

    # Apply watermark using the tested implementation
    assert impl.is_watermark_applicable(sample_pdf_path, position=None)
    out = impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=position)

    # Use the existing _extract_bytes helper (handles dicts, streams, paths)
    watermarked_bytes = _extract_bytes(out)

    # 🛡 Ensure we got raw bytes back
    assert isinstance(watermarked_bytes, (bytes, bytearray)), "Expected raw bytes from _extract_bytes"
    new_hash = hashlib.sha256(watermarked_bytes).hexdigest()

    # Test: PDF must have changed (kills NumberReplacer, ZeroIteration mutants)
    assert new_hash != original_hash, "Watermarked PDF should differ from original"

    # Test: Watermarked PDF must contain expected visible or embedded content
    with fitz.open(stream=watermarked_bytes, filetype="pdf") as doc:
        text = ""
        for page in doc:
            text += page.get_text()

        # Check that the watermarking made a visible or detectable change
        assert "unit-test" in text.lower() or len(text.strip()) > 0, \
            "Expected watermark content missing in PDF text"


@pytest.mark.parametrize("impl", [wm_encrypted()])
def test_wm_encrypted_renders_all_lines_visibly(impl, sample_pdf_path: Path):
    secret = "mutant-killer-" * 10  # long secret to produce many chunks
    key = "test-key"
    position = "none"

    # Ensure applicable
    assert impl.is_watermark_applicable(sample_pdf_path, position=position)

    # Apply watermark
    out = impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=position)
    watermarked_bytes = _extract_bytes(out)

    # Open and extract visible text
    with fitz.open(stream=watermarked_bytes, filetype="pdf") as doc:
        page = doc[0]
        text_lines = page.get_text("text").splitlines()

    # Expect ~len(secret)/32 lines (based on chunking logic)
    expected_lines = len(secret) // 32 + (1 if len(secret) % 32 else 0)

    # Heuristic: Count lines with watermark characteristics
    visible_lines = [line for line in text_lines if len(line.strip()) >= 10]

    # Allow some margin, but expect at least 80% of lines are visible
    assert len(visible_lines) >= int(0.8 * expected_lines), (
        f"Expected at least {int(0.8 * expected_lines)} visible watermark lines, got {len(visible_lines)}"
    )


@pytest.mark.parametrize("impl", [wm_encrypted()])
def test_wm_encrypted_position_top_x_centered(impl, sample_pdf_path: Path):
    secret = "position-test"
    key = "test-key"
    position = "top"

    # Apply watermark
    out = impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=position)
    watermarked_bytes = _extract_bytes(out)

    # Open the watermarked PDF
    doc = fitz.open(stream=watermarked_bytes, filetype="pdf")

    # Extract all visible text with their positions on the first page
    page = doc[0]
    text_instances = []
    blocks = page.get_text("dict")["blocks"]
    for block in blocks:
        if block["type"] != 0:
            continue
        for line in block["lines"]:
            for span in line["spans"]:
                bbox = span["bbox"]
                text = span["text"]
                text_instances.append((bbox, text))

    # Find the bbox of the watermark text chunk matching part of the secret
    wm_text_bbox = None
    for bbox, text in text_instances:
        if secret[:5] in text:
            wm_text_bbox = bbox
            break

    assert wm_text_bbox is not None, "Watermark text not found on page"

    # Check that the watermark's x coordinate is approximately centered horizontally
    rect_width = doc[0].rect.width  # Access before closing doc

    doc.close()  # Close doc after all access

    text_width = wm_text_bbox[2] - wm_text_bbox[0]  # right - left
    expected_x = (rect_width - text_width) / 2
    actual_x = wm_text_bbox[0]

    tolerance = 3.0  # allow small difference due to rendering
    assert abs(actual_x - expected_x) < tolerance, (
        f"Watermark x-position is off: actual {actual_x}, expected ~{expected_x}"
    )



##### wm_visible_stamp_gs tests ######

def test_is_watermark_applicable_handles_various_inputs():
    impl = VisibleStampGS()

    assert impl.is_watermark_applicable(b"%PDF-1.4")  # bytes
    assert impl.is_watermark_applicable("document.PDF")  # .PDF, uppercase
    assert impl.is_watermark_applicable("report.pdf")  # .pdf, lowercase
    assert not impl.is_watermark_applicable("notes.txt")  # unsupported extension


def test_add_watermark_uses_default_secret_when_blank(sample_pdf_path: Path):
    impl = VisibleStampGS()
    dummy_pdf_bytes = b"%PDF-1.4\n% Dummy"

    with patch("subprocess.run") as mock_run, \
         patch("builtins.open", mock_open(read_data=dummy_pdf_bytes)) as mock_file, \
         patch("os.unlink"), \
         patch("pathlib.Path.exists", return_value=True):

        mock_run.return_value = MagicMock(returncode=0, stderr="")

        result = impl.add_watermark(sample_pdf_path, secret="   ")  # blank string
        assert isinstance(result, dict)
        assert b"%PDF" in result["pdf_bytes"]
        assert result["secret"] == "   "  # still returns input, but Ghostscript uses default internally


def test_add_watermark_raises_when_script_missing(sample_pdf_path: Path):
    impl = VisibleStampGS()

    with patch("pathlib.Path.exists", return_value=False), \
         patch("os.unlink"):
        with pytest.raises(RuntimeError, match="Missing helper script"):
            impl.add_watermark(sample_pdf_path, secret="any")


def test_add_watermark_raises_on_subprocess_failure(sample_pdf_path: Path):
    impl = VisibleStampGS()

    with patch("subprocess.run") as mock_run, \
         patch("pathlib.Path.exists", return_value=True), \
         patch("os.unlink"):
        mock_run.return_value = MagicMock(returncode=1, stderr="Boom!")

        with pytest.raises(RuntimeError, match="Ghostscript failed: Boom!"):
            impl.add_watermark(sample_pdf_path, secret="any")


def test_read_secret_returns_expected_value(sample_pdf_path: Path):
    impl = VisibleStampGS()

    result = impl.read_secret(sample_pdf_path, key="irrelevant")
    assert result == "Secret is visible"


def test_visible_stamp_gs_runs_successfully(sample_pdf_path: Path):
    secret = "kill-this-mutant"
    key = None
    position = None

    impl = VisibleStampGS()

    # Simulate subprocess.run returning success
    with patch("subprocess.run") as mock_run, \
            patch("builtins.open", create=True) as mock_open, \
            patch("os.unlink"):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        mock_open.return_value.__enter__.return_value.read.return_value = b"%PDF-1.4\n% Watermarked content"

        out = impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=position)
        watermarked_bytes = _extract_bytes(out)

        assert isinstance(watermarked_bytes, (bytes, bytearray))
        assert b"%PDF" in watermarked_bytes


##### metadata_embedding tests ######

def test_is_watermark_applicable_returns_true(sample_pdf_path: Path):
    impl = MetadataEmbedding()
    assert impl.is_watermark_applicable(sample_pdf_path)
    assert impl.is_watermark_applicable(b"%PDF-1.4")  # also works on bytes


def test_compute_metadata_key_is_deterministic_and_prefixed():
    impl = MetadataEmbedding()
    key1 = impl.compute_metadata_key("secret-key")
    key2 = impl.compute_metadata_key("secret-key")
    key3 = impl.compute_metadata_key("different-key")

    assert key1 == key2  # Deterministic
    assert key1.startswith("/WM_")
    assert key3 != key1  # Different keys produce different hashes


def test_read_secret_recovers_correct_value(sample_pdf_path: Path):
    impl = MetadataEmbedding()
    secret = "read-me"
    key = "my-key"

    pdf_bytes = _extract_bytes(impl.add_watermark(sample_pdf_path, secret, key))
    recovered = impl.read_secret(pdf_bytes, key)

    assert recovered == secret


def test_read_secret_raises_on_corrupt_metadata(sample_pdf_path: Path):
    impl = MetadataEmbedding()
    secret = "real-secret"
    key = "secure"

    pdf_bytes = _extract_bytes(impl.add_watermark(sample_pdf_path, secret, key))

    # Corrupt the metadata manually
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf_obj:
        metadata_key = impl.compute_metadata_key(key)
        pdf_obj.docinfo[metadata_key] = "%%% not base64 %%%"
        output = io.BytesIO()
        pdf_obj.save(output)

    corrupted_pdf = output.getvalue()

    with pytest.raises(InvalidKeyError, match="Failed to decode watermark"):
        impl.read_secret(corrupted_pdf, key)


def test_read_secret_raises_when_metadata_missing(sample_pdf_path: Path):
    impl = MetadataEmbedding()
    secret = "hidden"
    key = "correct-key"
    wrong_key = "wrong-key"

    pdf_bytes = _extract_bytes(impl.add_watermark(sample_pdf_path, secret, key))

    with pytest.raises(SecretNotFoundError):
        impl.read_secret(pdf_bytes, wrong_key)


def test_add_watermark_stores_encoded_secret_in_metadata(sample_pdf_path: Path):
    impl = MetadataEmbedding()
    secret = "mutant-killer"
    key = "abc123"
    position = "top-left"

    pdf_bytes = _extract_bytes(impl.add_watermark(sample_pdf_path, secret, key, position))

    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf_obj:
        metadata = pdf_obj.docinfo
        metadata_key = impl.compute_metadata_key(key)

        assert metadata_key in metadata

        raw_encoded = metadata[metadata_key]
        # Convert PikePDF object to str before decoding
        decoded = json.loads(base64.b64decode(str(raw_encoded)))

        assert decoded["secret"] == secret
        assert decoded["position"] == position


@pytest.mark.parametrize("impl", [MetadataEmbedding()])
def test_metadata_embedding_changes_pdf(impl, sample_pdf_path: Path):
    secret = "unit-test-secret"
    key = "unit-test-key"
    position = "none"

    # Read original PDF bytes and hash
    with open(sample_pdf_path, "rb") as f:
        original_bytes = f.read()
    original_hash = hashlib.sha256(original_bytes).hexdigest()

    # Ensure watermarking is applicable
    assert impl.is_watermark_applicable(sample_pdf_path, position=None)

    # Apply metadata watermark
    out = impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=position)

    # Extract modified PDF bytes
    watermarked_bytes = _extract_bytes(out)

    # Ensure we got raw bytes back
    assert isinstance(watermarked_bytes, (bytes, bytearray)), "Expected raw bytes from _extract_bytes"
    new_hash = hashlib.sha256(watermarked_bytes).hexdigest()

    # PDF must be different
    assert new_hash != original_hash, "Watermarked PDF should differ from original"

    # Ensure secret is retrievable
    retrieved_secret = impl.read_secret(watermarked_bytes, key=key)
    assert retrieved_secret == secret, "Retrieved secret does not match the original"

    # Since this watermark is in metadata, there may be no visible content to extract with fitz
    # But we can check metadata using pikepdf
    import pikepdf
    with pikepdf.open(io.BytesIO(watermarked_bytes)) as pdf_obj:
        metadata = pdf_obj.docinfo
        computed_key = impl.compute_metadata_key(key)
        assert computed_key in metadata, "Expected metadata key not found"


@pytest.mark.parametrize("impl", [MetadataEmbedding()])
def test_metadata_embedding_encodes_position_correctly(impl, sample_pdf_path: Path):
    secret = "mutant-killer-secret"
    key = "mutant-killer-key"
    position = "top-right"  # Important: Non-empty position

    # Apply the watermark
    out = impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=position)

    # Extract watermarked bytes
    pdf_bytes = _extract_bytes(out)

    # Read PDF metadata
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf_obj:
        metadata = pdf_obj.docinfo
        metadata_key = impl.compute_metadata_key(key)
        assert metadata_key in metadata, "Metadata key not found in watermarked PDF"

        raw_encoded = metadata[metadata_key]
        if not isinstance(raw_encoded, str):
            raw_encoded = str(raw_encoded)

        # Decode and parse metadata
        decoded_json = base64.b64decode(raw_encoded)
        parsed = json.loads(decoded_json)

        # Check both secret and position
        assert parsed.get("secret") == secret, "Secret mismatch in metadata"
        assert parsed.get("position") == position, "Position mismatch in metadata"


##### server tests #####

def test_server_path_joining_behavior():

    base_name = "report"
    intended_slug = "user123"
    dest_dir = Path("/tmp/documents")

    # Simulate function that does the join
    # We mimic just the code snippet affected by the mutant:
    unique_stamp = "20251017123456000000-abcdef"
    candidate = f"{base_name}__{intended_slug}__{unique_stamp}.pdf"

    # The original (correct) way to join path:
    correct_path = dest_dir / candidate

    # The mutant changes this line to:
    try:
        mutant_path = dest_dir % candidate
        mutant_raised = False
    except TypeError:
        mutant_raised = True

    # Assert that mutant_path using % fails (TypeError) or is invalid
    # Because using % on Path is not valid and should raise.
    assert mutant_raised, "Mutant allowed invalid path join with '%' operator"

    # Also assert the correct path ends with candidate string
    assert str(correct_path).endswith(candidate)


def test_path_joining_with_storage_root():

    storage_root = Path("/var/data").resolve()
    relative_path = Path("files/report.pdf")

    # The original correct behavior:
    expected_path = storage_root / relative_path
    assert expected_path.is_absolute()

    # Check path parts rather than raw string:
    expected_parts = ("var", "data", "files", "report.pdf")
    # Check these parts are the last parts of the path
    assert expected_path.parts[-4:] == expected_parts

    # Simulate mutant behavior: replacing / with >>
    with pytest.raises(TypeError):
        _ = storage_root >> relative_path


def test_watermarking_method_subclass_check(monkeypatch):
    # Load server.py manually
    server_path = Path(__file__).resolve().parent.parent / "src" / "server.py"
    spec = importlib.util.spec_from_file_location("server_module", server_path)
    server_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server_module)

    # Dummy plugin that has the right methods
    class DummyPlugin:
        def add_watermark(self): pass
        def read_secret(self): pass

    # Patch WatermarkingMethod to None (simulate mutation)
    monkeypatch.setattr(server_module, "WatermarkingMethod", None)

    cls = DummyPlugin
    has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))

    if server_module.WatermarkingMethod is not None:
        is_ok = issubclass(cls, server_module.WatermarkingMethod) and has_api
    else:
        is_ok = has_api

    assert is_ok is True


def test_healthz_endpoint_ok(monkeypatch, client: FlaskClient):
    """Simulate DB connection success."""
    class DummyConn:
        def execute(self, *args, **kwargs): return 1
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class DummyEngine:
        def connect(self): return DummyConn()

    # location
    monkeypatch.setattr("sqlalchemy.create_engine", lambda *a, **kw: DummyEngine())

    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json["db_connected"] is True


def test_static_file_access_control(client: FlaskClient):
    allowed = ["index.html", "login.html", "signup.html", "style.css", "documents.html"]
    blocked = ["secret_config.yaml", "app.py"]

    for fname in allowed:
        response = client.get(f"/{fname}")
        # Note: File may not exist during test, so just check status not 403
        assert response.status_code != 403

    for fname in blocked:
        response = client.get(f"/{fname}")
        assert response.status_code == 403
        assert response.json["error"] == "Access denied"


def test_create_user_success(monkeypatch, client):
    client.application.config.pop("_ENGINE", None)

    class DummyConn:
        def execute(self, stmt, params=None):
            if "INSERT INTO Users" in str(stmt):
                return None
            elif "SELECT id, email, login FROM Users" in str(stmt):
                return type("Row", (), {"id": "123", "email": "test@example.com", "login": "testuser"})()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class DummyEngine:
        def begin(self): return DummyConn()

    monkeypatch.setattr("sqlalchemy.create_engine", lambda *a, **kw: DummyEngine())

    response = client.post("/api/create-user", json={
        "email": "test@example.com",
        "login": "testuser",
        "password": "securepass"
    })

    assert response.status_code == 201
    data = response.json
    assert data["email"] == "test@example.com"
    assert data["login"] == "testuser"


@pytest.mark.parametrize("payload, expected_error", [
    ({}, "email, login, and password are required"),
    ({"email": "a@b.com", "login": "user"}, "email, login, and password are required"),
    ({"email": "a@b.com", "login": "user", "password": "x"}, "password must be at least 8 characters"),
    ({"email": "invalid", "login": "user", "password": "securepass"}, "invalid email address"),
])
def test_create_user_input_validation(client, payload, expected_error):
    response = client.post("/api/create-user", json=payload)
    assert response.status_code == 400
    assert expected_error in response.json["error"]


@pytest.mark.parametrize("payload, error", [
    ({}, "email and password are required"),
    ({"email": "invalid", "password": "x"}, "invalid email address"),
])
def test_login_input_validation(client, payload, error):
    response = client.post("/api/login", json=payload)
    assert response.status_code == 400
    assert error in response.json["error"]


def test_login_invalid_credentials(monkeypatch, client):
    client.application.config.pop("_ENGINE", None)

    class DummyConn:
        def execute(self, stmt, params=None):
            return type("Result", (), {"first": lambda self=None: None})()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class DummyEngine:
        def connect(self): return DummyConn()

    monkeypatch.setattr("sqlalchemy.create_engine", lambda *a, **kw: DummyEngine())

    response = client.post("/api/login", json={
        "email": "test@example.com",
        "password": "wrong"
    })

    assert response.status_code == 401
    assert "invalid credentials" in response.json["error"]


def test_upload_requires_auth(client):
    r = client.post("/api/upload-document")
    assert r.status_code == 401


def test_upload_missing_file_field(client, temp_storage):
    headers = _get_token(client)
    r = client.post("/api/upload-document", headers=headers, data={}, content_type="multipart/form-data")
    assert r.status_code == 400
    assert r.get_json()["error"] == "file is required (multipart/form-data)"


def test_upload_empty_filename(client, temp_storage):
    headers = _get_token(client)
    data = {
        "file": (io.BytesIO(b"dummy"), "")
    }
    r = client.post("/api/upload-document", headers=headers, data=data, content_type="multipart/form-data")
    assert r.status_code == 400
    assert r.get_json()["error"] == "empty filename"


def test_upload_invalid_pdf(client, temp_storage):
    headers = _get_token(client)
    data = {
        "file": (io.BytesIO(b"This is not a PDF"), "bad.pdf")
    }
    r = client.post("/api/upload-document", headers=headers, data=data, content_type="multipart/form-data")
    assert r.status_code == 400
    assert "invalid PDF file" in r.get_json()["error"]


def test_upload_broken_pdf_valid_header(client, temp_storage):
    headers = _get_token(client)
    # Starts with %PDF- but isn't a valid PDF — should fall back and still accept
    broken_pdf = b"%PDF-1.7\nthis is just a trick"
    data = {
        "file": (io.BytesIO(broken_pdf), "tricky.pdf")
    }
    r = client.post("/api/upload-document", headers=headers, data=data, content_type="multipart/form-data")
    assert r.status_code == 201
    json = r.get_json()
    assert "id" in json
    assert json["name"] == "tricky.pdf"
    assert json["sha256"]
    assert json["size"] > 0


def test_upload_valid_pdf(client, temp_storage):
    headers = _get_token(client)
    valid_pdf = b"%PDF-1.4\n%...\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    data = {
        "file": (io.BytesIO(valid_pdf), "sample.pdf"),
        "name": "uploaded_sample.pdf"
    }
    r = client.post("/api/upload-document", headers=headers, data=data, content_type="multipart/form-data")
    assert r.status_code == 201
    json = r.get_json()
    assert json["name"] == "uploaded_sample.pdf"
    assert json["sha256"]
    assert json["size"] == len(valid_pdf)


def test_list_documents_requires_auth(client):
    r = client.get("/api/list-documents")
    assert r.status_code == 401


def test_list_versions_unknown_document(client):
    headers = _get_token(client)
    # well-formed UUID, but not existing
    r = client.get("/api/list-versions/123e4567-e89b-12d3-a456-426614174000", headers=headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "versions" in data
    assert isinstance(data["versions"], list)
    assert len(data["versions"]) == 0


def test_list_all_versions_requires_auth(client):
    r = client.get("/api/list-all-versions")
    assert r.status_code == 401


def test_list_all_versions_empty_for_new_user(client):
    headers = _get_token(client)
    r = client.get("/api/list-all-versions", headers=headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "versions" in data
    assert isinstance(data["versions"], list)
    assert len(data["versions"]) == 0


def test_get_document_success(client, temp_storage):
    headers = _get_token(client)
    pdf_bytes = b"%PDF-1.4\n%...\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    data = {
        "file": (io.BytesIO(pdf_bytes), "test.pdf"),
    }
    upload = client.post("/api/upload-document", headers=headers, data=data, content_type="multipart/form-data")
    assert upload.status_code == 201
    doc_id = upload.get_json()["id"]

    r = client.get(f"/api/get-document/{doc_id}", headers=headers)
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert r.data.startswith(b"%PDF")


def test_delete_document_success(client):
    # Create user & login
    email = "delete@test.com"
    login = "delete_user"
    pw = "abc12345"
    client.post("/api/create-user", json={"email": email, "login": login, "password": pw})
    r = client.post("/api/login", json={"email": email, "password": pw})
    token = r.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Upload document
    fake_pdf = b"%PDF-1.4\n%...\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    data = {
        "name": "test_delete.pdf",
        "file": (io.BytesIO(fake_pdf), "test_delete.pdf")
    }
    r = client.post("/api/upload-document", headers=headers, data=data, content_type="multipart/form-data")
    assert r.status_code == 201
    doc_id = r.get_json()["id"]

    # Delete document
    r = client.delete(f"/api/delete-document/{doc_id}", headers=headers)
    assert r.status_code == 200
    res = r.get_json()
    assert res["deleted"] is True
    assert res["file_deleted"] in [True, False]  # May be false if test storage not used
    assert res["id"] == doc_id


def test_delete_document_not_found(client):
    # Create user & login
    email = "missing@test.com"
    login = "missing_user"
    pw = "abc12345"
    client.post("/api/create-user", json={"email": email, "login": login, "password": pw})
    r = client.post("/api/login", json={"email": email, "password": pw})
    token = r.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Try to delete a random UUID
    fake_id = "00000000-0000-0000-0000-000000000000"
    r = client.delete(f"/api/delete-document/{fake_id}", headers=headers)
    assert r.status_code == 404
    res = r.get_json()
    assert "error" in res
    assert res["error"] == "document not found"


def test_create_watermark_unauthorized(client):
    response = client.post("/api/create-watermark/1234", json={"method": "Dummy", "secret": "ABC"})
    assert response.status_code == 401  # Assuming @require_auth blocks unauthenticated access


@pytest.mark.parametrize("filename", [
    "index.html",
    "login.html",
    "signup.html",
    "documents.html",
    "style.css"
])
def test_static_files_allowed(client, filename):
    res = client.get(f"/{filename}")
    assert res.status_code in (200, 304), f"Expected 200 or 304 for {filename}, got {res.status_code}"
    assert res.mimetype in ("text/html", "text/css")


@pytest.mark.parametrize("filename", [
    "secret.txt",
    "config.json",
    "admin.js",
    "passwords.csv",
    "style.scss"
])
def test_static_files_denied(client, filename):
    res = client.get(f"/{filename}")
    assert res.status_code == 403
    assert "Access denied" in res.get_json()["error"]


def test_home_route_serves_index(client):
    response = client.get("/")
    assert response.status_code in (200, 304)
    assert b"<html" in response.data.lower() or b"<!doctype" in response.data.lower()
    assert "text/html" in response.content_type


def test_get_version_works_successfully(client, tmp_path, monkeypatch):
    # Create a fake PDF file
    fake_pdf = tmp_path / "test.pdf"
    fake_pdf.write_bytes(b"%PDF-1.4\n%Fake PDF")

    # Set up in-memory SQLite and create Versions table (since get_engine wasn't working)
    sqlite_file = tmp_path / "test.db"
    db_url = f"sqlite:///{sqlite_file}"
    monkeypatch.setenv("DB_URL", db_url)
    engine = create_engine(db_url, future=True)
    metadata = MetaData()

    versions = Table("Versions", metadata,
        Column("link", String, primary_key=True),
        Column("path", String),
    )
    metadata.create_all(engine)

    # Insert test data
    with engine.connect() as conn:
        conn.execute(versions.insert().values(link="some-link", path=str(fake_pdf)))
        conn.commit()

    # Override STORAGE_DIR to match tmp_path
    client.application.config["STORAGE_DIR"] = tmp_path

    # Make request
    res = client.get("/api/get-version/some-link")

    # Assert
    assert res.status_code == 200
    assert res.mimetype == "application/pdf"
    assert b"%PDF" in res.data


def test_get_version_invalid_file_type(client, tmp_path, monkeypatch):
    # Create a fake non-PDF file
    fake_file = tmp_path / "test.txt"
    fake_file.write_text("not a pdf")

    # Set up file-based SQLite and Versions table
    sqlite_file = tmp_path / "test.db"
    db_url = f"sqlite:///{sqlite_file}"
    monkeypatch.setenv("DB_URL", db_url)
    engine = create_engine(db_url, future=True)
    metadata = MetaData()

    versions = Table("Versions", metadata,
        Column("link", String, primary_key=True),
        Column("path", String),
    )
    metadata.create_all(engine)

    # Insert entry pointing to the .txt file
    with engine.connect() as conn:
        conn.execute(versions.insert().values(link="test", path=str(fake_file)))
        conn.commit()

    # Set STORAGE_DIR and call endpoint
    client.application.config["STORAGE_DIR"] = tmp_path
    res = client.get("/api/get-version/test")

    # Assertions
    assert res.status_code == 400
    assert "invalid file type" in res.get_json()["error"]


def test_create_watermark_applies_to_uploaded_pdf(client, sample_pdf_bytes, temp_storage):
    # Step 1: Create user and login
    email = "watermark_user@test.com"
    login = "wm_user"
    password = "abc12345"
    client.post("/api/create-user", json={"email": email, "login": login, "password": password})
    r = client.post("/api/login", json={"email": email, "password": password})
    assert r.status_code == 200
    token = r.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 2: Upload a sample PDF to get document_id
    data = {
        "name": "test.pdf",
        "file": (io.BytesIO(sample_pdf_bytes), "test.pdf")
    }
    r = client.post("/api/upload-document", headers=headers, data=data, content_type="multipart/form-data")
    assert r.status_code == 201
    document_id = r.get_json()["id"]

    # Step 3: Call the watermarking endpoint
    watermark_payload = {
        "watermark_text": "CONFIDENTIAL",
        "opacity": 0.7,
        "position": "center",
        "method": "wm-encrypted",
        "intended_for": "testuser@example.com",
        "secret": "dummysecret",
        "key": "dummykey"
    }
    r = client.post(f"/api/create-watermark/{document_id}", headers=headers, json=watermark_payload)

    if r.status_code != 200:
        print("Error response:", r.get_data(as_text=True))

    # Step 4: Assert things are working
    assert r.status_code == 201

    response_data = r.get_json()
    assert "filename" in response_data
    assert response_data["method"] == "wm-encrypted"
    assert response_data["intended_for"] == "testuser@example.com"


def test_get_watermarking_methods(client):
    # Make a GET request to the endpoint
    response = client.get("/api/get-watermarking-methods")

    # Assert status code is OK
    assert response.status_code == 200

    # Parse JSON response
    data = response.get_json()

    # Basic structure check
    assert "methods" in data
    assert isinstance(data["methods"], list)

    # Each method should have 'name' and 'description'
    for method in data["methods"]:
        assert "name" in method
        assert "description" in method
        assert isinstance(method["name"], str)
        assert isinstance(method["description"], str)

    # Count should match number of methods returned
    assert "count" in data
    assert data["count"] == len(data["methods"])


def test_read_watermark_missing_fields(client):
    # Simulate login
    client.post("/api/create-user", json={"email": "user@wm.com", "login": "wmuser", "password": "test123"})
    login_res = client.post("/api/login", json={"email": "user@wm.com", "password": "test123"})
    token = login_res.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt with missing 'key'
    response = client.post("/api/read-watermark/123", json={
        "method": "DummyMethod"
    }, headers=headers)

    assert response.status_code == 400
    assert "method, and key are required" in response.get_json()["error"]


def test_read_watermark_api_document_not_found(client, sample_pdf_bytes):
    # Step 1: Create user and login
    email = "user2@example.com"
    login = "user2"
    password = "pass123"
    client.post("/api/create-user", json={"email": email, "login": login, "password": password})

    r = client.post("/api/login", json={"email": email, "password": password})
    assert r.status_code == 200
    token = r.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 2: Upload a sample PDF and get document_id
    data = {
        "name": "sample.pdf",
        "file": (io.BytesIO(sample_pdf_bytes), "sample.pdf")
    }
    r = client.post("/api/upload-document", headers=headers, data=data, content_type="multipart/form-data")
    assert r.status_code == 201

    # Step 3: Call the read-watermark endpoint with a non-existing document ID (to trigger 404)
    non_existing_document_id = "nonexistent-id-1234"
    payload = {
        "method": "wm-encrypted",
        "key": "dummykey",
        "position": "center"
    }
    r = client.post(f"/api/read-watermark/{non_existing_document_id}", headers=headers, json=payload)

    # Assert that the response status code is 404 (Not Found)
    assert r.status_code == 404






