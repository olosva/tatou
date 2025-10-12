import io
import fitz  # PyMuPDF
import os
import json
import base64
from typing import Optional

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes, is_pdf_bytes,
    derive_key, encrypt, decrypt, get_coordinates
    
)

#from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#import secrets


class wm_encrypted(WatermarkingMethod):
    name = "wm-encrypted"

    @staticmethod
    def get_usage() -> str:
        return "Encrypted watermarking method: visible text + hidden encrypted secret"

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        return True

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """
        Return a new PDF with a visible watermark and a hidden encrypted secret.
        """
        #print(">> add_watermark called")
        
        # Derive a 256-bit key from the provided key, we store the salt and iv in the database
        
        
       # print("Derived key and salt:")
        pdf_bytes = load_pdf_bytes(pdf)
        stamped_pdf = self.add_visible_watermark(pdf_bytes, position, secret)
        
        key, salt = derive_key(key)
       
        encrypted_secret, nonce, tag = encrypt(secret, key)
    
        final_pdf = self.add_hidden_watermark(stamped_pdf, encrypted_secret,position)
        #return final_pdf, salt, nonce, tag to add to the database
        #ALLA MÅSTE NOG RETURNERA EN DICT MED PDF BYTES FÖR ATT DET SKA FUNKA
        print(salt, nonce, tag)
        return {
            "pdf_bytes": final_pdf,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "secret": base64.b64encode(encrypted_secret).decode("ascii")
        }
    
    
    def read_secret(self, pdf, key, position, iv, tag, salt):
        import base64
        import fitz  # PyMuPDF

        # --- normalisera crypto-parametrar: stöd både bytes och ev. base64-strängar ---
        def _norm(x):
            # bytes -> använd som är (om ASCII-base64: decoda)
            if isinstance(x, (bytes, bytearray)):
                try:
                    s = x.decode("ascii")
                    if all(c.isalnum() or c in "+/=" for c in s):
                        return base64.b64decode(s)
                    return bytes(x)
                except UnicodeDecodeError:
                    return bytes(x)
            # str -> försök base64-dekoda, annars treat-as-bytes
            if isinstance(x, str):
                try:
                    return base64.b64decode(x)
                except Exception:
                    return x.encode()
            return x

        salt = _norm(salt)
        iv   = _norm(iv)
        tag  = _norm(tag)

        derived_key, _ = derive_key(key, salt)

        # --- ladda PDF ---
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        if doc.page_count == 0:
            raise ValueError("PDF has no pages")

        # --- hämta text-chunks där hemligheten gömts ---
        x, y0 = get_coordinates(position, doc[0].rect)
        line_height = 7  # måste matcha add_hidden_watermark

        chunks = []
        for page in doc:
            y = y0
            while y < page.rect.height:
                rect = fitz.Rect(
                    max(x - 5, 0),
                    max(y - 3, 0),
                    min(x + 400, page.rect.width),
                    min(y + 20, page.rect.height),
                )
                text_dict = page.get_text("dict", clip=rect)
                text = "".join(
                    span.get("text", "")
                    for block in text_dict.get("blocks", [])
                    if block.get("type") == 0
                    for line in block.get("lines", [])
                    for span in line.get("spans", [])
                )
                if not text.strip():
                    break  # slut på chunk-raden

                # spara enbart base64-tecken
                clean_chunk = "".join(c for c in text if c.isalnum() or c in "+/=")
                if clean_chunk:
                    chunks.append(clean_chunk)
                y += line_height

        doc.close()

        if not chunks:
            raise ValueError("No hidden chunks found at expected positions")

        # --- sätt ihop alla base64-chunks + fixa padding ---
        b64 = "".join(chunks)
        pad = (-len(b64)) % 4
        if pad:
            b64 += "=" * pad

        try:
            ciphertext = base64.b64decode(b64, validate=False)
        except Exception as e:
            raise ValueError(f"Failed to decode hidden base64: {e}")

        try:
            return decrypt(ciphertext, derived_key, iv, tag)
        except Exception as e:
            raise ValueError(f"Failed to decrypt secret: {e}")

        


    def add_visible_watermark(self, pdf_bytes, position, secret):
        pdf = fitz.open(stream=pdf_bytes, filetype="pdf")

        for page in pdf:
            rect = page.rect
            font_size = 36
            font_name = "helv"

            # Estimate text width
            text_width = fitz.get_text_length(secret, fontname=font_name, fontsize=font_size)

            if position == "center":
                x = (rect.width - text_width) / 2
                y = rect.height / 2
                rotate = 45
            elif position == "top":
                x = (rect.width - text_width) / 2
                y = rect.height * 0.1
                rotate = 0
            elif position == "bottom":
                x = (rect.width - text_width) / 2
                y = rect.height * 0.9
                rotate = 0
            else:
                # Fallback to center
                x = (rect.width - text_width) / 2
                y = rect.height / 2
                rotate = 0

            page.insert_text(
                (x, y),
                secret,
                fontsize=font_size,
                rotate=rotate,
                color=(0.7, 0.7, 0.7),  # light gray
                render_mode=2,  # fill + stroke
                fontname=font_name,
                # align=1,  # Optional: Not used with absolute positioning
                # opacity=0.3
            )

        out = io.BytesIO()
        pdf.save(out, deflate=True)
        return out.getvalue()
    
    def add_hidden_watermark(self, pdf_bytes, secret, position):
        #print("kommer in hidden")
        blob_b64 = base64.b64encode(secret).decode("ascii")
        # chunk to avoid huge single strings
        chunk_size = 64
        chunks = [blob_b64[i : i + chunk_size] for i in range(0, len(blob_b64), chunk_size)]

        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        #page = doc[0] if doc.page_count > 0 else doc.new_page()
        #rect = page.rect
        x, y0 = get_coordinates(position, doc[0].rect)
        
        for page in doc:
        # small font, invisible rendering mode (render_mode=3)
        #x = rect.width * 0.02
        #y0 = rect.height * 0.02
            line_height = 7
            fontsize = 6
            for i, chunk in enumerate(chunks):
                y = y0 + i * line_height
                page.insert_text((x, y), chunk, fontsize=fontsize, fontname="helv", render_mode=3)
                print(x, y)
        out = io.BytesIO()
        doc.save(out, deflate=True)
        doc.close()
        return out.getvalue()

    