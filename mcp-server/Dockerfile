FROM python:3.12-slim

WORKDIR /app

# System deps (curl for healthcheck; certs already bundled)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Unbuffered output so docker logs streams in real time.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Default to SSE transport on 8800 (override with args).
EXPOSE 8800
CMD ["python", "-m", "src.main", "--transport", "sse"]

# /healthz is a plain JSON 200 endpoint with no auth — safe to probe from
# the Docker healthcheck without embedding the API key. --max-time 3 prevents
# hangs if the server is stuck.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -sf --max-time 3 \
        http://127.0.0.1:${MCP_HTTP_PORT:-8800}/healthz || exit 1
