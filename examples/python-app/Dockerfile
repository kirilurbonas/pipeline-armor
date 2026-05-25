# =============================================================================
# Multi-stage Dockerfile for the Python example.
#
# Stage 1 builds a virtualenv so the runtime image never needs pip / build
# tooling. Stage 2 copies the venv into a slim runtime image and runs as a
# non-root user.
# =============================================================================

# ---- Build ----------------------------------------------------------------
FROM python:3.12.7-slim-bookworm AS builder

# Stop pip from creating __pycache__ inside the venv and from writing the
# usual chatty progress bars to the build log.
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# ---- Runtime --------------------------------------------------------------
FROM python:3.12.7-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Create a dedicated, low-privilege user. Distroless would be nicer but
# uvicorn's stdlib imports are easier to reason about on a real Debian
# slim — the trade-off is documented in docs/security-gates.md.
RUN groupadd --system app && useradd --system --gid app --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app src ./src

USER app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)" \
  || exit 1

CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8080"]
