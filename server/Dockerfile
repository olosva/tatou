# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src:${PYTHONPATH}

WORKDIR /app

<<<<<<< HEAD
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Copy project description, to instal dependencies
=======
# OS-deps: Ghostscript (för watermark) + bash
RUN apt-get update \
 && apt-get install -y --no-install-recommends ghostscript bash \
 && rm -rf /var/lib/apt/lists/*

# Projektfiler (src-layout)
>>>>>>> develliot
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY flag /app/flag
<<<<<<< HEAD
COPY entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e .

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]
=======

# Python-deps + app (editable) + gunicorn
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -e . \
 && pip install --no-cache-dir gunicorn

# Se till att stämpel-skriptet är körbart (om du lagt in det)
RUN chmod +x /app/src/wm_stamp.sh || true

EXPOSE 5000

# Kör servern
CMD ["gunicorn", "-b", "0.0.0.0:5000", "server:app"]
>>>>>>> develliot

