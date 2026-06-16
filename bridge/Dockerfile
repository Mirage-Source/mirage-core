# Enrichment worker image: the Python ML layer + the bridge.
# Build context is the repo root (mirage real source/) so we can COPY both ml/
# and bridge/. See ../docker-compose.yml.

FROM python:3.12-slim AS runtime

WORKDIR /app

# System deps: psycopg2-binary ships wheels, but keep build-essential off the
# image; we rely on the binary wheel. libgomp is needed by torch/sklearn.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install torch from the CPU wheel index first (largest layer, cache-friendly).
RUN pip install --no-cache-dir \
    --index-url https://download.pytorch.org/whl/cpu \
    "torch>=2.1"

# Bridge + ML runtime deps.
COPY bridge/requirements.txt /app/bridge/requirements.txt
RUN pip install --no-cache-dir -r /app/bridge/requirements.txt

# The assembled ML package, installed so `import mirage` works anywhere.
COPY ml/ /app/ml/
RUN pip install --no-cache-dir /app/ml

# The bridge code.
COPY bridge/ /app/bridge/

# Non-root.
RUN useradd --system --no-create-home mirage && chown -R mirage /app
USER mirage

ENTRYPOINT ["python", "-m", "bridge.worker"]
