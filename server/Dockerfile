# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Git behövs för "rmap @ git+..."
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Kopiera projektfiler
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY flag /app/flag
COPY entrypoint.sh /app/entrypoint.sh

# Installera beroenden/projektet (PEP 660 editable)
RUN pip install --no-cache-dir -e .

# Skapa ett "server"-paket som pekar på src.server
RUN mkdir -p /app/server \
 && printf "from src.server import create_app\n" > /app/server/__init__.py

# Gör entrypoint körbar och fixa ev. CRLF
RUN chmod +x /app/entrypoint.sh && sed -i 's/\r$//' /app/entrypoint.sh

EXPOSE 5000

CMD ["./entrypoint.sh"]
