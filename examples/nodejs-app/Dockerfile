# =============================================================================
# Multi-stage Dockerfile for the Node.js example.
#
# Stage 1 (builder)   : install full dependency tree with dev tooling so we
#                       can build / test if needed.
# Stage 2 (runtime)   : copy only production deps + source into a distroless
#                       image. Final image runs as a non-root user with no
#                       shell, which neutralizes most container-escape
#                       chains.
# =============================================================================

# ---- Build ----------------------------------------------------------------
FROM node:20.18.1-alpine AS builder

WORKDIR /app

# Copy lockfiles first to maximize cache hits when src/ changes.
COPY package.json package-lock.json* ./

# `npm ci` is reproducible and fails the build if package-lock.json drifts.
RUN npm ci --omit=dev --no-audit --no-fund

COPY src ./src

# ---- Runtime --------------------------------------------------------------
# Distroless gives us a minimal attack surface — no shell, no package
# manager, no busybox. Trivy will still scan it because language packages
# are detected via the manifest, not the OS layer.
FROM gcr.io/distroless/nodejs20-debian12:nonroot

WORKDIR /app

# Non-root by default in distroless `nonroot` variant — UID 65532.
COPY --from=builder --chown=nonroot:nonroot /app /app

USER nonroot

EXPOSE 8080

# Liveness signal for orchestrators.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "require('http').get('http://127.0.0.1:8080/healthz', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]

CMD ["src/app.js"]
