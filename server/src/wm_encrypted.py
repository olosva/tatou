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
        print(">> add_watermark called")
        
        # Derive a 256-bit key from the provided key, we store the salt and iv in the database
        
        
       # print("Derived key and salt:")
        pdf_bytes = load_pdf_bytes(pdf)
        stamped_pdf = self.add_visible_watermark(pdf_bytes, position, secret)
        
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
            "encrypted_secret": base64.b64encode(encrypted_secret).decode("ascii")
        }
    
    
    def read_secret(self, pdf_bytes: PdfSource, key:str, position:str):
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        page = doc[0] if doc.page_count > 0 else doc.new_page()
        rect = page.rect
        x,y0 = get_coordinates(position, rect)
        
        return None  # Not implemented for this method
        


    def add_visible_watermark(self, pdf_bytes, position, secret):
        print("kommer in visible")
        pdf = fitz.open(stream=pdf_bytes, filetype="pdf")
        for page in pdf:
            rect = page.rect
            if position == "center":
                x, y = rect.width / 2, rect.height / 2
                align = 1  # center
            elif position == "top":
                x, y = rect.width / 2, rect.height * 0.1
                align = 1
            elif position == "bottom":
                x, y = rect.width / 2, rect.height * 0.9
                align = 1
            else:  # fallback: center
                x, y = rect.width / 2, rect.height / 2
                align = 1

            page.insert_text(
                (x, y), 
                secret, 
                fontsize=36, 
                rotate=45 if position == "center" else 0, 
                color=(0.7, 0.7, 0.7),  # light gray
                render_mode=2,  # fill + stroke
                fontname="helv"
                #align=align,
                #opacity=0.3
            )

        out = io.BytesIO()
        pdf.save(out, deflate=True)
        return out.getvalue()
    
    def add_hidden_watermark(self, pdf_bytes, secret, position):
        print("kommer in hidden")
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
        out = io.BytesIO()
        doc.save(out, deflate=True)
        doc.close()
        return out.getvalue()

    