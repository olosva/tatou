
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src:${PYTHONPATH}

WORKDIR /app

# Install dependencies (bash, ghostscript needed for watermarking)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    openssh-client \
    bash \
    ghostscript \
 && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY flag /app/flag
COPY src/pki /app/server/pki
COPY src/server_private_key /app/server/server_private_key
COPY wm_stamp.sh /app/src/wm_stamp.sh
COPY entrypoint.sh /app/entrypoint.sh

# Ensure scripts are executable and have Unix line endings
RUN chmod +x /app/entrypoint.sh /app/src/wm_stamp.sh \
 && sed -i 's/\r$//' /app/entrypoint.sh /app/src/wm_stamp.sh

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Gunicorn shim
RUN mkdir -p /app/server \
 && printf "from src.server import create_app\n" > /app/server/__init__.py

EXPOSE 5000
CMD ["./entrypoint.sh"]

