FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src:${PYTHONPATH}

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY flag /app/flag
COPY pki /app/server/pki
COPY server_private_key /app/server/server_private_key
COPY entrypoint.sh /app/entrypoint.sh

RUN pip install --no-cache-dir -e .

# Shim för gunicorn 'server:create_app()'
RUN mkdir -p /app/server \
 && printf "from src.server import create_app\n" > /app/server/__init__.py

RUN chmod +x /app/entrypoint.sh && sed -i 's/\r$//' /app/entrypoint.sh

EXPOSE 5000
CMD ["./entrypoint.sh"]
