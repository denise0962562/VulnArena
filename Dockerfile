FROM node:24-alpine AS frontend
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml requirements.lock README.md ./
COPY vulnarena ./vulnarena
COPY --from=frontend /vulnarena/web ./vulnarena/web
RUN pip wheel --no-cache-dir --wheel-dir /wheels -c requirements.lock '.[ai]'

FROM python:3.12-slim AS ai-dependencies
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.lock requirements-ai.lock ./
COPY scripts/setup_ai_runtime.py ./scripts/setup_ai_runtime.py
RUN pip install --no-cache-dir -c requirements.lock httpx packaging \
    && python scripts/setup_ai_runtime.py

FROM python:3.12-slim AS runtime-base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels 'vulnarena[ai]' \
    && rm -rf /wheels \
    && groupadd --gid 10001 vulnarena \
    && useradd --uid 10001 --gid vulnarena --no-create-home vulnarena \
    && mkdir -p /app/data && chown 10001:10001 /app/data
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]
CMD ["uvicorn", "vulnarena.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

FROM runtime-base AS ai
USER root
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ai-dependencies /build/.tools/ai-runtime /opt/vulnarena-ai
COPY scripts/setup_ai_embedding.py scripts/verify_ai_runtime.py /app/scripts/
ENV VULNARENA_AI_EMBEDDING_PYTHON=/opt/vulnarena-ai/bin/python \
    HF_HOME=/tmp/huggingface FASTEMBED_CACHE_PATH=/tmp/fastembed
USER 10001:10001

# Default image stays lightweight. Select --target ai for isolated CPU inference.
FROM runtime-base AS runtime
