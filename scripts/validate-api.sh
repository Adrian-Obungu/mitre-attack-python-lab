#!/bin/bash

# This script validates the FastAPI server endpoints.
# It starts the API server, tests its functionality, and then shuts it down.

# --- Configuration ---
# Load environment variables from .env if present
if [ -f .env ]; then
    export $(cat .env | xargs)
fi

API_KEY=${API_KEY:-"my-secret-api-key"} # Default API key if not set in .env
API_SERVER_PORT=${API_SERVER_PORT:-8080} # Default port if not set in .env
HONEYPOT_METRICS_PORT=${HONEYPOT_METRICS_PORT:-8000} # Default port for honeypot metrics

API_URL="http://localhost:${API_SERVER_PORT}"

# --- Utility Functions ---
log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[SUCCESS] $1"
}

log_error() {
    echo "[ERROR] $1"
    exit 1
}

# --- Cleanup Function ---
cleanup() {
    log_info "Cleaning up..."
    if [ -n "$API_PID" ]; then
        kill "$API_PID"
        log_info "API server (PID $API_PID) stopped."
    fi
    exit $1
}

trap 'cleanup 1' ERR INT TERM

# --- Main Validation Script ---

log_info "Starting API server in the background on port ${API_SERVER_PORT}..."
# Ensure uvicorn is installed. Use python -m uvicorn
python -m uvicorn src.api_server:app --host 0.0.0.0 --port "${API_SERVER_PORT}" > /dev/null 2>&1 &
API_PID=$!
log_info "API server started with PID ${API_PID}. Waiting for it to become ready..."

# Wait for the API server to be ready
ATTEMPTS=0
MAX_ATTEMPTS=10
until curl -s "${API_URL}/health" > /dev/null; do
    if [ ${ATTEMPTS} -eq ${MAX_ATTEMPTS} ]; then
        log_error "API server did not become ready after ${MAX_ATTEMPTS} attempts."
    fi
    sleep 2
    ATTEMPTS=$((ATTEMPTS+1))
done
log_success "API server is ready."

# 1. Test GET /health endpoint
log_info "Testing GET /health endpoint..."
HEALTH_RESPONSE=$(curl -s -H "X-API-Key: ${API_KEY}" "${API_URL}/health")
if echo "${HEALTH_RESPONSE}" | grep -q "operational"; then
    log_success "GET /health successful."
else
    log_error "GET /health failed: ${HEALTH_RESPONSE}"
fi

# 2. Test POST /scan endpoint
log_info "Testing POST /scan endpoint..."
SCAN_TARGET="scanme.nmap.org"
SCAN_PORTS="80"
SCAN_TYPE="ack"
SCAN_RESPONSE=$(curl -s -X POST \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"target\": \"${SCAN_TARGET}\", \"ports\": \"${SCAN_PORTS}\", \"scan_type\": \"${SCAN_TYPE}\"}" \
    "${API_URL}/scan")

if echo "${SCAN_RESPONSE}" | grep -q "Port scan initiated successfully"; then
    log_success "POST /scan successful for ${SCAN_TARGET}:${SCAN_PORTS} (${SCAN_TYPE})."
else
    log_error "POST /scan failed: ${SCAN_RESPONSE}"
fi

# 3. Test GET /reports endpoint for enriched IP data
log_info "Testing GET /reports endpoint for enriched IP data..."
# Run the log parser to generate a report (this will also perform TI lookups)
REPORT_RESPONSE=$(curl -s -H "X-API-Key: ${API_KEY}" "${API_URL}/reports")

# Check if the report contains threat_reputation for at least one IP
if echo "${REPORT_RESPONSE}" | jq 'any(.threat_reputation != null)' | grep -q "true"; then
    log_success "GET /reports successful and contains 'threat_reputation' data."
else
    log_error "GET /reports failed or does not contain expected 'threat_reputation' data: ${REPORT_RESPONSE}"
fi

# 4. Test GET /metrics endpoint
log_info "Testing GET /metrics endpoint..."
METRICS_RESPONSE=$(curl -s -H "X-API-Key: ${API_KEY}" "${API_URL}/metrics")
if echo "${METRICS_RESPONSE}" | grep -q "dns_queries_total"; then # Check for a known Prometheus metric
    log_success "GET /metrics successful."
else
    log_error "GET /metrics failed or did not return expected Prometheus metrics: ${METRICS_RESPONSE}"
fi

log_success "All API validation tests passed!"

cleanup 0
