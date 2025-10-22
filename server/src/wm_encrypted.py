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
        position = position or "center"  # default fallback
        
        
        
        
       
        pdf_bytes = load_pdf_bytes(pdf)
        stamped_pdf = self.add_visible_watermark(pdf_bytes, position, secret)
        
        # Derive a 256-bit key from the provided key, we store the salt and iv in the database
        key, salt = derive_key(key)
       
        encrypted_secret, nonce, tag = encrypt(secret, key)
    
        final_pdf = self.add_hidden_watermark(stamped_pdf, encrypted_secret,position)
        #return final_pdf, salt, nonce, tag to add to the database
        #ALLA MÅSTE NOG RETURNERA EN DICT MED PDF BYTES FÖR ATT DET SKA FUNKA
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

        position = position or "center"  # default fallback
       #iv, tag, and salt can arrive as bytes, base64 strings or plain ASCII
       #the _norm() function normalizes them to bytes so that decrypt always receive correct values
        def _norm(x):
            # bytes -> use as is  (if ASCII-base64: decode)
            if isinstance(x, (bytes, bytearray)):
                try:
                    s = x.decode("ascii")
                    if all(c.isalnum() or c in "+/=" for c in s):
                        return base64.b64decode(s)
                    return bytes(x)
                except UnicodeDecodeError:
                    return bytes(x)
            
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

 
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        if doc.page_count == 0:
            raise ValueError("PDF has no pages")

      
        x, y0 = get_coordinates(position, doc[0].rect)
        line_height = 7

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
                    break  

                clean_chunk = "".join(c for c in text if c.isalnum() or c in "+/=")
                if clean_chunk:
                    chunks.append(clean_chunk)
                y += line_height

        doc.close()

        if not chunks:
            raise ValueError("No hidden chunks found at expected positions")

        # PyMuPDF sometimes returns line breaks or non-base64 characters
        # We now strip all invalid characters and fix missing padding so decoding never fails with incorrect padding
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
                rotate = 0
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
                
            )

        out = io.BytesIO()
        pdf.save(out, deflate=True)
        return out.getvalue()
    
    def add_hidden_watermark(self, pdf_bytes, secret, position):
        
        blob_b64 = base64.b64encode(secret).decode("ascii")
        # chunk to avoid huge single strings
        chunk_size = 64
        chunks = [blob_b64[i : i + chunk_size] for i in range(0, len(blob_b64), chunk_size)]

        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        x, y0 = get_coordinates(position, doc[0].rect)
        
        for page in doc:
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

    