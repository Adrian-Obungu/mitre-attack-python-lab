#!/bin/bash
# MITRE ATT&CK Lab Debugging Commands

echo "1. Check API health directly:"
curl -v http://127.0.0.1:8000/health 2>&1 | grep -E "(HTTP|< HTTP)"

echo ""
echo "2. Test authentication:"
curl -v -H "X-API-Key: demo-key-2024" http://127.0.0.1:8000/dashboard/api/metrics 2>&1 | tail -5

echo ""
echo "3. Check if detectors exist:"
find src/ -name "*.py" -type f | grep -E "(detector|discovery|lateral)" | head -10

echo ""
echo "4. Check Python path and imports:"
python -c "import sys; print('Python path:'); [print(f'  {p}') for p in sys.path[:5]]"
python -c "try: from src.defense_evasion.obfuscation_detector import T1027ObfuscationDetector; print('✅ T1027 imports OK'); except Exception as e: print(f'❌ T1027 import failed: {e}')"

echo ""
echo "5. Check API server logs:"
tail -10 api_server.log 2>/dev/null || echo "No API log found"

echo ""
echo "6. Verify file structure:"
ls -la src/api/ src/defense_evasion/ src/discovery/ 2>/dev/null || echo "Some directories missing"
