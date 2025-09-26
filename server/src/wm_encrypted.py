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
    
    
   # def read_secret(self, pdf, key, position, iv, tag, salt):
        #print("kommer in read_secret")
       
        salt = base64.b64decode(salt)
        iv = base64.b64decode(iv)
        tag = base64.b64decode(tag)
        #x,y0 = get_coordinates(position, rect)
        print(iv, tag, salt)
        derived_key, _ = derive_key(key, salt)
        
        pdf_bytes = load_pdf_bytes(pdf)

        
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        
    
        if doc.page_count == 0:
            raise ValueError("PDF has no pages")

        # Get coordinates where text was embedded
        x, y0 = get_coordinates(position, doc[0].rect)
        line_height = 7

        # Extract text from known positions
        chunks = []
        for page_num, page in enumerate(doc):
            chunk_index = 0
            while True:
                y = y0 + chunk_index * line_height

                # Ensure rectangle stays within page boundaries
                rect = fitz.Rect(
                    max(x - 5, 0),
                    max(y - 3, 0),
                    min(x + 400, page.rect.width),
                    min(y + 20, page.rect.height)  # slightly taller to catch font
                )

                # Try extracting text from the rectangle
                try:
                    text = page.get_textbox(rect)

                    # fallback: extract text via dictionary
                    if not text.strip():
                        text_dict = page.get_text("dict", clip=rect)
                        text = ""
                        for block in text_dict.get("blocks", []):
                            if block.get("type") == 0:  # text block
                                for line in block.get("lines", []):
                                    for span in line.get("spans", []):
                                        text += span.get("text", "")

                    print(f"Page {page_num}, chunk_index {chunk_index}, extracted: {repr(text)}")

                    if not text.strip():
                        break  # No more chunks on this page

                    # Clean extracted text to match base64 chars
                    clean_chunk = ''.join(c for c in text if c.isalnum() or c in '+/=')

                    # Accept chunks that are at least 50 chars (allows small extraction variance)
                    if len(clean_chunk) >= 50:
                        chunks.append(clean_chunk[:64])
                        chunk_index += 1
                    else:
                        break  # likely no more hidden text

                except Exception as e:
                    print(f"Error reading chunk at index {chunk_index} on page {page_num}: {e}")
                    break

        doc.close()

        if not chunks:
            
            raise ValueError("No hidden chunks found at expected positions")

        # Reassemble base64 data
        encrypted_secret = ''.join(chunks)

        try:
            # Decode and decrypt
            #encrypted_secret = base64.b64decode(encrypted_data_b64)
            
            
            encrypted_secret_bytes = base64.b64decode(encrypted_secret)
            #encrypted_secret_bytes = base64.b64decode('xbwYSY4=')
            decrypted_secret = decrypt(encrypted_secret_bytes, derived_key, iv, tag)
            print(decrypted_secret)
            
            #print(decrypted_secret)
            return decrypted_secret

        except Exception as e:
            raise ValueError(f"Failed to decrypt secret: {str(e)}")


    def read_secret(self, pdf, key, position, iv, tag, salt):
        import base64
        import fitz  # PyMuPDF

        print("Starting read_secret")

        # Decode crypto params
        salt = base64.b64decode(salt)
        iv = base64.b64decode(iv)
        tag = base64.b64decode(tag)
        derived_key, _ = derive_key(key, salt)

        # Load PDF
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        if doc.page_count == 0:
            raise ValueError("PDF has no pages")

        # Get coordinates where watermark was inserted
        x, y0 = get_coordinates(position, doc[0].rect)
        line_height = 7  # must match add_hidden_watermark

        chunks = []

        for page_num, page in enumerate(doc):
            y = y0
            while y < page.rect.height:
                rect = fitz.Rect(
                    max(x - 5, 0),
                    max(y - 3, 0),
                    min(x + 400, page.rect.width),
                    min(y + 20, page.rect.height)
                )

                # Extract text from region
                text_dict = page.get_text("dict", clip=rect)
                text = "".join(
                    span.get("text", "")
                    for block in text_dict.get("blocks", [])
                    if block.get("type") == 0
                    for line in block.get("lines", [])
                    for span in line.get("spans", [])
                )

                if not text.strip():
                    break  # stop when no more text found at this Y

                # Keep only base64-valid chars
                clean_chunk = ''.join(c for c in text if c.isalnum() or c in '+/=')

                if clean_chunk:
                    chunks.append(clean_chunk)
                    print(f"Page {page_num}, y={y}, extracted: {clean_chunk}")

                y += line_height  # move down to next expected chunk line

        doc.close()

        if not chunks:
            raise ValueError("No hidden chunks found at expected positions")

        # TODO compare each chunk so that the secret is the same on all pages?
        encrypted_secret_b64 = chunks[0]
        try:
            encrypted_secret_bytes = base64.b64decode(encrypted_secret_b64)
            decrypted_secret = decrypt(encrypted_secret_bytes, derived_key, iv, tag)
            #print("Decrypted secret:", decrypted_secret)
            return decrypted_secret
        except Exception as e:
            raise ValueError(f"Failed to decrypt secret: {e}")
        


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
                fontname="helv",
                #align=align,
                #opacity=0.3
            )
            #print(x, y)

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

    