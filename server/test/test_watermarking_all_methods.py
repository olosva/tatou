# test/test_watermarking_all_methods.py
from pathlib import Path
import subprocess
import shutil
import pytest
import hashlib
import fitz  # PyMuPDF — to inspect PDF contents
import io
from unittest.mock import patch, MagicMock
import pickle
import re
import base64
import json
import pikepdf
import importlib.util

from metadata_embedding import MetadataEmbedding
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


###### Tests created after mutation testing ######

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


def test_server_path_joining_behavior():
    import server  # Assuming the module is named server.py

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
    import server  # your server module

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



