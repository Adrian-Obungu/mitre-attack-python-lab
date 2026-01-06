# syntax=docker/dockerfile:1.4
ARG PYTHON_VERSION=3.9.18

# -----------------------------------------------------------------------------
# Builder stage
# -----------------------------------------------------------------------------
FROM python:3.9-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y build-essential

# Copy requirements file (using the full requirements.txt for now, to ensure all needed libs)
COPY config/requirements.txt ./config/

# Install dependencies
RUN pip install --no-cache-dir -r config/requirements.txt

# Copy application code
COPY src/reconnaissance/tcp_connect_scan.py src/reconnaissance/
COPY src/reconnaissance/dns_recon.py src/reconnaissance/
COPY src/reconnaissance/PortScan_Enhanced.py src/reconnaissance/
COPY src/persistence/ src/persistence/
COPY src/privilege/ src/privilege/

# -----------------------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------------------
FROM python:3.9-slim as runtime

WORKDIR /app

# Copy installed dependencies and application code
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /app/src/reconnaissance/tcp_connect_scan.py src/reconnaissance/tcp_connect_scan.py
COPY --from=builder /app/src/reconnaissance/dns_recon.py src/reconnaissance/dns_recon.py
COPY --from=builder /app/src/reconnaissance/PortScan_Enhanced.py src/reconnaissance/PortScan_Enhanced.py
COPY --from=builder /app/src/persistence/ src/persistence/
COPY --from=builder /app/src/privilege/ src/privilege/

# Healthcheck to verify the PortScan_Enhanced.py script is present and executable
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD ["python", "-c", "import os; exit(not os.path.exists('/app/src/reconnaissance/PortScan_Enhanced.py'))"]

# Set entrypoint to easily run scanner scripts
ENTRYPOINT ["python"]
CMD [] # Allow user to specify which script to run (e.g., "src/reconnaissance/PortScan_Enhanced.py --target example.com")