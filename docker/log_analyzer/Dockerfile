# syntax=docker/dockerfile:1.4
ARG PYTHON_VERSION=3.9.18

# -----------------------------------------------------------------------------
# Builder stage
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-alpine as builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache build-base

# Copy requirements file
COPY config/requirements.txt ./config/

# Install dependencies
RUN pip install --no-cache-dir -r config/requirements.txt

# Copy application code and configuration
COPY src/utils/log_parser.py src/utils/
COPY config/threat_scores.json config/

# -----------------------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-alpine as runtime

WORKDIR /app

# Copy installed dependencies and application code
COPY --from=builder /usr/local/lib/python${PYTHON_VERSION}/site-packages /usr/local/lib/python${PYTHON_VERSION}/site-packages
COPY --from=builder /app/src/utils/log_parser.py src/utils/log_parser.py
COPY --from=builder /app/config/threat_scores.json config/threat_scores.json
RUN mkdir -p logs/ # Ensure logs directory exists for accessing log files

# Set up entrypoint for the log analyzer
ENTRYPOINT ["python", "src/utils/log_parser.py"]
CMD ["logs/honeyresolver.log"] # Default log file to analyze
