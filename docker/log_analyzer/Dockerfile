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

# Copy application code and configuration
COPY src/utils/log_parser.py src/utils/
COPY config/threat_scores.json config/

# -----------------------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------------------
FROM python:3.9-slim as runtime

WORKDIR /app

# Copy installed dependencies and application code
# Using python3.9 path is more robust than a specific micro version
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /app/src/utils/log_parser.py src/utils/log_parser.py
COPY --from=builder /app/config/threat_scores.json config/threat_scores.json
RUN mkdir -p logs/ # Ensure logs directory exists for accessing log files

# Set up entrypoint for the log analyzer
ENTRYPOINT ["python", "src/utils/log_parser.py"]
CMD ["logs/honeyresolver.log"] # Default log file to analyze
