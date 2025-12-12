# syntax=docker/dockerfile:1.4
ARG PYTHON_VERSION=3.9.18

# -----------------------------------------------------------------------------
# Builder stage
# -----------------------------------------------------------------------------
FROM python:3.9-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y build-essential

# Copy requirements file (using the slimmed-down requirements-docker.txt for production)
COPY config/requirements-docker.txt ./config/

# Install dependencies
RUN pip install --no-cache-dir -r config/requirements-docker.txt

# Copy application code
COPY src/reconnaissance/tcp_connect_scan.py src/reconnaissance/
COPY src/reconnaissance/dns_recon.py src/reconnaissance/

# -----------------------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------------------
FROM python:3.9-slim as runtime

WORKDIR /app

# Copy installed dependencies and application code
COPY --from=builder /usr/local/lib/python${PYTHON_VERSION}/site-packages /usr/local/lib/python${PYTHON_VERSION}/site-packages
COPY --from=builder /app/src/reconnaissance/tcp_connect_scan.py src/reconnaissance/tcp_connect_scan.py
COPY --from=builder /app/src/reconnaissance/dns_recon.py src/reconnaissance/dns_recon.py

# Set entrypoint to easily run scanner scripts
ENTRYPOINT ["python"]
CMD [] # Allow user to specify which script to run (e.g., "src/reconnaissance/tcp_connect_scan.py --target example.com")
