# -----------------------------------------------------------------------------
# Dockerfile for FastAPI API Server
# -----------------------------------------------------------------------------
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements file and install Python dependencies
# Using config/requirements.txt which contains all dependencies
COPY config/requirements.txt ./config/
RUN pip install --no-cache-dir -r config/requirements.txt

# Copy application code
# Ensure all dependencies for api_server.py are copied
COPY src/api_server.py src/
COPY src/utils/threat_intel.py src/utils/
COPY src/utils/log_parser.py src/utils/
COPY src/reconnaissance/PortScan_Enhanced.py src/reconnaissance/

# Copy configuration files needed by log_parser (threat_scores.json)
COPY config/threat_scores.json config/threat_scores.json

# Ensure logs directory exists for log_parser
RUN mkdir -p logs/

# Expose the API server port
# API_SERVER_PORT defaults to 8080, but can be set via env var
EXPOSE 8080

# Healthcheck to verify the API server is running
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD curl -f http://localhost:8080/health || exit 1

# Command to run the FastAPI application
# Use environment variables for configuration
CMD ["uvicorn", "src.api_server:app", "--host", "0.0.0.0", "--port", "8080"]
