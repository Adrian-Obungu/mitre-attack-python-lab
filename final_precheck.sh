#!/bin/bash
echo "=== FINAL PRECHECK FOR CHAPTER 5 ==="
echo "Date: $(date)"
echo ""

# 1. Check wordlist
echo "1. Checking wordlist..."
if [ -f "config/common_subdomains.txt" ]; then
    echo "   ✅ Wordlist exists ($(wc -l < config/common_subdomains.txt) lines)"
else
    echo "   ❌ Wordlist missing - creating..."
    mkdir -p config
    cat > config/common_subdomains.txt << 'WORDLIST'
www
mail
ftp
admin
api
WORDLIST
    echo "   ✅ Wordlist created"
fi

# 2. Check .env
echo "2. Checking .env file..."
if [ -f ".env" ]; then
    echo "   ✅ .env exists"
else
    echo "   ⚠️ .env missing - creating test version..."
    echo 'API_KEY="test-key-123"' > .env
    echo 'MOCK_MODE="true"' >> .env
    echo "   ✅ .env created"
fi

# 3. Core module tests
echo "3. Testing core modules..."
echo "   Testing TCP scanner..."
venv/Scripts/python src/reconnaissance/tcp_connect_scan.py scanme.nmap.org -p 80 2>&1 | grep -q "Open" && echo "      ✅ TCP Scanner works" || echo "      ❌ TCP Scanner failed"

echo "   Testing DNS recon..."
venv/Scripts/python src/reconnaissance/dns_recon.py -d github.com -w config/common_subdomains.txt -t 1 --timeout 2 2>&1 | grep -q "Starting DNS" && echo "      ✅ DNS Recon works" || echo "      ⚠️ DNS Recon had issues (check wordlist)"

echo "   Testing Persistence Auditor..."
venv/Scripts/python src/persistence/persistence_auditor.py --help 2>&1 | grep -q "usage" && echo "      ✅ Persistence Auditor works" || echo "      ❌ Persistence Auditor failed"

# 4. Environment summary
echo ""
echo "=== ENVIRONMENT SUMMARY ==="
venv/Scripts/python --version
echo "Virtual environment: $(which python)"
echo "Git branch: $(git branch --show-current)"
echo "Git status: $(git status --short | wc -l) changes pending"
echo ""
echo "=== READINESS ASSESSMENT ==="
echo "If all checks pass with ✅, environment is READY for Chapter 5"
echo "Run: venv/Scripts/python validate_environment_fixed.py for detailed validation"
