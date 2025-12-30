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

# Copy application code and configuration
COPY src/defense/HoneyResolver_Enhanced.py src/defense/
COPY config/honeypot_config.json config/

# -----------------------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------------------
FROM python:3.9-slim as runtime

WORKDIR /app

# Copy installed dependencies and application code
# Using python3.9 path is more robust than a specific micro version
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /app/src/defense/HoneyResolver_Enhanced.py src/defense/HoneyResolver_Enhanced.py
COPY --from=builder /app/config/honeypot_config.json config/honeypot_config.json
RUN mkdir -p logs/ # Ensure logs directory exists for FileHandler

# Expose ports
EXPOSE 8053
EXPOSE 8000 # For health checks / metrics (will be added later)

# Install curl for healthcheck
RUN apt-get update && apt-get install -y curl --no-install-recommends && rm -rf /var/lib/apt/lists/*

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD curl -f http://localhost:8000/health || exit 1

# Command to run the honeypot
CMD ["python", "src/defense/HoneyResolver_Enhanced.py"]
