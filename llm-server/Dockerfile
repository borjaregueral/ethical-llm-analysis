# ═══════════════════════════════════════════════════════════════════════════════
# llm-server — Multi-stage build
#
# Build args:
#   MODEL_MODE=mock     → installs only FastAPI/uvicorn/pydantic  (~80 MB image)
#   MODEL_MODE=instruct → also installs torch + transformers + accelerate (~4 GB)
#
# Build examples:
#   docker build --build-arg MODEL_MODE=mock     -t llm-server:mock .
#   docker build --build-arg MODEL_MODE=instruct -t llm-server:instruct .
# ═══════════════════════════════════════════════════════════════════════════════

ARG MODEL_MODE=mock

# ── Stage 1: dependency installation ──────────────────────────────────────────
FROM python:3.11-slim AS deps

ARG MODEL_MODE

WORKDIR /deps

# Copy requirements first — these layers are cached until files change
COPY requirements-mock.txt requirements-full.txt ./

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements-mock.txt \
 && if [ "$MODEL_MODE" != "mock" ]; then \
        pip install --no-cache-dir -r requirements-full.txt; \
    fi

# ── Stage 2: minimal runtime image ────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Create non-root user (UID/GID 1001)
RUN groupadd -r -g 1001 llmuser \
 && useradd  -r -u 1001 -g llmuser -d /workspace -s /sbin/nologin llmuser

WORKDIR /workspace

# Copy installed packages from deps stage (no build tools in runtime image)
COPY --from=deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=deps /usr/local/bin                           /usr/local/bin

# Copy application source — owned by non-root user
COPY --chown=llmuser:llmuser app/ ./app/

USER llmuser

EXPOSE 8000

# Health check via Python stdlib — curl not available in slim image
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
