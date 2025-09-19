from __future__ import annotations
import io, os, tempfile, subprocess
from pathlib import Path
from typing import Optional
from watermarking_method import WatermarkingMethod, PdfSource, load_pdf_bytes

class VisibleStampGS(WatermarkingMethod):
    """Synlig diagonal watermark via Ghostscript."""
    name = "visible-stamp-gs"

    def get_usage(self) -> str:
        return "Visible diagonal text stamp using Ghostscript (fast, robust)."

    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        if isinstance(pdf, (bytes, bytearray)):
            return True
        return str(pdf).lower().endswith(".pdf")

    def add_watermark(self, pdf: PdfSource, secret: str, key: Optional[str] = None, position: Optional[str] = None) -> bytes:
        text = (secret or "").strip() or "Tatou"
        data = load_pdf_bytes(pdf)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as fin:
            fin.write(data)
            in_path = fin.name
        out_fd, out_path = tempfile.mkstemp(suffix=".pdf"); os.close(out_fd)

        try:
            script = Path(__file__).with_name("wm_stamp.sh")
            if not script.exists():
                raise RuntimeError(f"Missing helper script: {script}")
            cmd = ["bash", str(script), in_path, out_path, text]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"Ghostscript failed: {res.stderr.strip()}")
            with open(out_path, "rb") as f:
                return f.read()
        finally:
            for p in (in_path, out_path):
                try: os.unlink(p)
                except Exception: pass

    def read_secret(self, pdf: PdfSource, key: Optional[str] = None, position: Optional[str] = None) -> Optional[str]:
        # Synlig stämpel – inget programmässigt att läsa ut.
        return None
