# -----------------------------------------------------------------------------
# Builder stage
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-alpine as builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache build-base

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
FROM python:${PYTHON_VERSION}-alpine as runtime

WORKDIR /app

# Copy installed dependencies and application code
COPY --from=builder /usr/local/lib/python${PYTHON_VERSION}/site-packages /usr/local/lib/python${PYTHON_VERSION}/site-packages
COPY --from=builder /app/src/defense/HoneyResolver_Enhanced.py src/defense/HoneyResolver_Enhanced.py
COPY --from=builder /app/config/honeypot_config.json config/honeypot_config.json
RUN mkdir -p logs/ # Ensure logs directory exists for FileHandler

# Expose ports
EXPOSE 8053
EXPOSE 8000 # For health checks / metrics (will be added later)

# Command to run the honeypot
CMD ["python", "src/defense/HoneyResolver_Enhanced.py"]
