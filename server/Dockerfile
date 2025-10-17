FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src:${PYTHONPATH} \
    STORAGE_DIR=/app/storage
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies (bash, ghostscript needed for watermarking)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    openssh-client \
    bash \
    ghostscript \
 && rm -rf /var/lib/apt/lists/*

# Copy build metadata first (better cache for pip install)
COPY pyproject.toml /app/pyproject.toml
COPY openapi.yml /app/openapi.yml
COPY src /app/src
COPY flag /app/flag
COPY test /app/test

# (Behåll) tidigare kopior till /app/server/...
COPY src/pki /app/server/pki
COPY src/server_private_key /app/server/server_private_key

# (+) Lägg även nycklar där server.py förväntar sig dem: /app/src/...
COPY src/pki /app/src/pki
COPY src/server_private_key /app/src/server_private_key

COPY wm_stamp.sh /app/src/wm_stamp.sh
COPY entrypoint.sh /app/entrypoint.sh

# Ensure scripts are executable and have Unix line endings
RUN chmod +x /app/entrypoint.sh /app/src/wm_stamp.sh \
 && sed -i 's/\r$//' /app/entrypoint.sh /app/src/wm_stamp.sh

# Install Python dependencies
RUN python -m pip install -U pip setuptools wheel \
 && pip install -e ".[dev]"


# Gunicorn shim (behålls) + säkerställ storage-katalogen finns
RUN mkdir -p /app/server /app/storage \
 && [ -f /app/server/__init__.py ] || printf "from src.server import create_app\n" > /app/server/__init__.py

EXPOSE 5000
CMD ["./entrypoint.sh"]
