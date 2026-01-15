#!/bin/bash

# Exit on any error
set -e

echo "================================="
echo "  Running Local Security Scan  "
echo "================================="

# --- Security Scans ---
echo ""
echo "--- Running Bandit Security Scan (High Severity) ---"
bandit -r src/ -s B101 -lll

echo ""
echo "--- Running Safety Dependency Scan ---"
safety check --file=requirements.txt --bare
safety check --file=config/requirements.txt --bare
echo "✅ Dependency scans passed."

# --- Docker Builds ---
echo ""
echo "--- Building Docker Images ---"
docker build -t mitre-api -f docker/api/Dockerfile .
docker build -t mitre-honeypot -f docker/honeypot/Dockerfile .
docker build -t mitre-log-analyzer -f docker/log_analyzer/Dockerfile .
docker build -t mitre-scanner -f docker/scanner/Dockerfile .
echo "✅ Docker images built successfully."

# --- API Test ---
echo ""
echo "--- Running Basic API Test ---"

# Start API server in background
echo "Starting API server..."
python -m uvicorn src.api.main:app --port 8000 &
API_PID=$!
# Wait for the server to start, checking health endpoint
for i in {1..10}; do
    if curl -s -f http://localhost:8000/health > /dev/null; then
        echo "API server started."
        break
    fi
    sleep 1
done

if ! curl -s -f http://localhost:8000/health > /dev/null; then
    echo "❌ API server failed to start."
    kill $API_PID
    exit 1
fi

echo "API health check passed."
kill $API_PID
echo "API server stopped."
echo "✅ API test complete."

echo ""
echo "🎉 Security scan script finished successfully! 🎉"
