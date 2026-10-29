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
RUN pip wheel --no-cache-dir --wheel-dir /wheels -c requirements.lock .

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels vulnarena \
    && rm -rf /wheels \
    && groupadd --gid 10001 vulnarena \
    && useradd --uid 10001 --gid vulnarena --no-create-home vulnarena
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]
CMD ["uvicorn", "vulnarena.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
