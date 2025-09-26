import base64
import hashlib
import io
import json
import os
import re
from watermarking_method import WatermarkingMethod, PdfSource, load_pdf_bytes, is_pdf_bytes, SecretNotFoundError, \
    InvalidKeyError
from typing import Any, Dict, Final, Iterable, List, Mapping
import pikepdf

"""Required interface
------------------
Concrete implementations must subclass :class:WatermarkingMethod and
implement the two abstract methods:

add_watermark(pdf, secret, key, position) -> bytes
    Produce a new watermarked PDF (as bytes) by embedding the
    provided secret using the given key. The optional position
    string can include method‑specific placement or strategy hints.

read_secret(pdf, key) -> str
    Recover and return the embedded secret from the given PDF using the
    provided key. Implementations should raise
    :class:SecretNotFoundError when no recognizable watermark is
    present and :class:InvalidKeyError when the key is incorrect."""


class MetadataEmbedding(WatermarkingMethod):

    @staticmethod
    def get_usage() -> str:
        return "metadata embedding"

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True

    def compute_metadata_key(
            self,
            key: str
    ) -> str:
        """Create a consistent metadata key to store the secret."""
        hashed_key = hashlib.sha256(key.encode()).hexdigest()
        return f"/WM_{hashed_key[:16]}"  # PDF metadata keys must start with "/"

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Embed the secret in the PDF's metadata."""
        data = load_pdf_bytes(pdf)

        with pikepdf.open(io.BytesIO(data)) as pdf_obj:
            metadata = pdf_obj.docinfo

            # Generate a unique key for storing the secret
            metadata_key = self.compute_metadata_key(key)

            # Combine the secret and position into a JSON string
            embedded_data = {
                "secret": secret,
                "position": position or ""
            }
            encoded = base64.b64encode(json.dumps(embedded_data).encode()).decode()

            # Store in metadata
            metadata[metadata_key] = encoded

            # Save modified PDF to memory
            output = io.BytesIO()
            pdf_obj.save(output)

        pdf_bytes = output.getvalue()
        return {"pdf_bytes": pdf_bytes, "secret": secret}

    def read_secret(
            self,
            pdf: PdfSource,
            key: str,
            position = None,
            iv = None,
            tag = None,
            salt = None
    ) -> str:
        """Read the secret from metadata using the given key."""
        data = load_pdf_bytes(pdf)

        with pikepdf.open(io.BytesIO(data)) as pdf_obj:
            metadata = pdf_obj.docinfo
            metadata_key = self.compute_metadata_key(key)

            if metadata_key not in metadata:
                raise SecretNotFoundError("No watermark metadata found.")

            try:
                raw_value = metadata[metadata_key]

                # Convert to str if it's a pikepdf.Object or any non-string type
                if not isinstance(raw_value, str):
                    raw_value = str(raw_value)

                decoded = base64.b64decode(raw_value)
                parsed = json.loads(decoded)

                return parsed.get("secret", "")
            except Exception as e:
                raise InvalidKeyError("Failed to decode watermark: " + str(e))





