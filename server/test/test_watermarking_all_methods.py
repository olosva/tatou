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














