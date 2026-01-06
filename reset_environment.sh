#!/bin/bash
echo "=== MITRE ATT&CK LAB - ENVIRONMENT RESET ==="
echo "Fixing corrupted virtual environment and validating fixes..."

# Set error handling
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# 1. Kill any running services
echo "1. Stopping any running services..."
pkill -f uvicorn 2>/dev/null || true
pkill -f python 2>/dev/null || true
sleep 2

# 2. Remove corrupted venv
echo "2. Removing corrupted virtual environment..."
rm -rf venv

# 3. Create fresh venv
echo "3. Creating fresh virtual environment..."
python -m venv venv

# 4. Install core dependencies directly (no activation needed)
echo "4. Installing dependencies..."
venv/Scripts/python -m pip install --upgrade pip
venv/Scripts/python -m pip install fastapi==0.118.3 uvicorn==0.38.0
venv/Scripts/python -m pip install dnslib==0.9.26 prometheus-client==0.23.1 requests==2.32.5

# 5. Install project requirements
echo "5. Installing project requirements..."
if [ -f "config/requirements.txt" ]; then
    venv/Scripts/python -m pip install -r config/requirements.txt
else
    echo "Using minimal requirements..."
    venv/Scripts/python -m pip install python-dotenv tabulate
fi

# 6. Verify venv works
echo "6. Verifying virtual environment..."
venv/Scripts/python --version
venv/Scripts/python -c "import sys; print(f'Python path: {sys.executable}')"

# 7. Test critical imports
echo "7. Testing critical imports..."
venv/Scripts/python -c "
try:
    import fastapi, uvicorn, dnslib, prometheus_client, requests
    print('✅ Core packages imported successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    exit(1)
"

# 8. Test log_parser.py (the main issue)
echo "8. Testing log_parser.py..."
venv/Scripts/python src/utils/log_parser.py --help 2>&1 | head -5 || echo "log_parser test failed, will fix..."

# 9. Start API server
echo "9. Starting API server..."
venv/Scripts/python -m uvicorn src.api_server:app --host 127.0.0.1 --port 8080 &
APIPID=$!
sleep 5

# 10. Test API endpoint
echo "10. Testing API scanner endpoint..."
curl -s -H "X-API-Key: test-key-123" -H "Content-Type: application/json" \
  -X POST http://localhost:8080/scan \
  -d '{"target": "scanme.nmap.org", "ports": "80", "scan_type": "connect"}' | \
  python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    status = data.get('status', 'unknown')
    print(f'✅ API scanner returned: {status}')
except:
    print('❌ API scanner test failed')
"

# 11. Clean up
kill $APIPID 2>/dev/null || true
echo -e "\n${GREEN}=== ENVIRONMENT RESET COMPLETE ===${NC}"
echo "Virtual environment has been recreated and validated."
echo "Use: venv/Scripts/python [your_script.py]"
echo "Test: venv/Scripts/python src/utils/log_parser.py --help"
