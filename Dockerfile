# Production Multi-Stage Dockerfile for TrustMesh Zero-Trust Node
FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY trustmesh/ ./trustmesh/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Final runtime image
FROM python:3.11-slim as runner

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY trustmesh/ ./trustmesh/
COPY dashboard/ ./dashboard/
COPY examples/ ./examples/
COPY security/ ./security/
COPY benchmarks/ ./benchmarks/
COPY run_dashboard.py ./

ENV TRUSTMESH_ENV=production \
    TRUSTMESH_PORT=8000 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

ENTRYPOINT ["python", "run_dashboard.py"]
