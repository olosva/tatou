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
            "encrypted_secret": base64.b64encode(encrypted_secret).decode("ascii")
        }
    
    
    def read_secret(self, pdf, key, position, iv, tag, salt):
        print("kommer in read_secret")
        #doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        #page = doc[0] if doc.page_count > 0 else doc.new_page()
        
        #x,y0 = get_coordinates(position, rect)
        derived_key = derive_key(base64.b64decode(key), base64.b64decode(salt))
        
        doc = fitz.open(stream=pdf, filetype="pdf")
        rect = page.rect
    
        if doc.page_count == 0:
            raise ValueError("PDF has no pages")

        # Get coordinates where text was embedded
        x, y0 = get_coordinates(position, rect)
        line_height = 7

        # Extract text from known positions
        chunks = []
        for page in doc:
            # Try to extract text from the area where we embedded it
            # Create small rectangles around each expected chunk position
            chunk_index = 0
            while True:
                y = y0 + chunk_index * line_height

                # Create a small rectangle around expected text position
                rect = fitz.Rect(x - 5, y - 3, x + 400, y + 10)  # Wide enough for 64-char chunk

                # Extract text from this specific area
                try:
                    # Try different extraction methods
                    text = page.get_textbox(rect)
                    if not text.strip():
                        # Try alternative method
                        text_dict = page.get_text("dict", clip=rect)
                        text = ""
                        for block in text_dict.get("blocks", []):
                            if block.get("type") == 0:
                                for line in block.get("lines", []):
                                    for span in line.get("spans", []):
                                        text += span.get("text", "")

                    if text.strip():
                        # Clean up and validate chunk
                        clean_chunk = ''.join(c for c in text if c.isalnum() or c in '+/=')
                        if len(clean_chunk) >= 60:  # Reasonable chunk size
                            chunks.append(clean_chunk[:64])  # Take first 64 chars
                            chunk_index += 1
                        else:
                            break
                    else:
                        break

                except:
                    break
                
        doc.close()

        if not chunks:
            raise ValueError("No hidden chunks found at expected positions")

        # Reassemble base64 data
        encrypted_data_b64 = ''.join(chunks)

        try:
            # Decode and decrypt
            encrypted_secret = base64.b64decode(encrypted_data_b64)
            salt = base64.b64decode(salt)
            nonce = base64.b64decode(iv)
            tag = base64.b64decode(tag)

            #derived_key, _ = derive_key(user_key, salt=salt)
            decrypted_secret = decrypt(encrypted_secret, derived_key, nonce, tag)

            return decrypted_secret.decode('utf-8')

        except Exception as e:
            raise ValueError(f"Failed to decrypt secret: {str(e)}")



        


    def add_visible_watermark(self, pdf_bytes, position, secret):
        #print("kommer in visible")
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
        out = io.BytesIO()
        doc.save(out, deflate=True)
        doc.close()
        return out.getvalue()

    