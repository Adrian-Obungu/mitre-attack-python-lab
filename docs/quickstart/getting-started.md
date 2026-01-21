# Getting Started with MITRE ATT&CK Lab

## Installation

### Option 1: Pip Install (Recommended)
\`\`\`bash
# Clone repository
git clone https://github.com/Adrian-Obungu/mitre-attack-python-lab.git
cd mitre-attack-python-lab

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Mac/Linux)
source venv/bin/activate

# Install with development dependencies
pip install -e ".[dev]"
\`\`\`

### Option 2: Docker
\`\`\`bash
# Build and run with Docker
docker build -t mitre-attack-lab .
docker run -p 8000:8000 mitre-attack-lab
\`\`\`

## Basic Usage

### 1. Run the API Server
\`\`\`bash
python src/api/main.py
# Server runs at http://localhost:8000
\`\`\`

### 2. Test Authentication
\`\`\`bash
curl -H "X-API-Key: demo-key-2024" http://localhost:8000/health
\`\`\`

### 3. Run Detectors Directly
\`\`\`bash
# Test obfuscation detector
python -c "
from src.defense_evasion.obfuscation_detector import T1027ObfuscationDetector
detector = T1027ObfuscationDetector()
result = detector.analyze({'process_name': 'test.exe'})
print(result)
"
\`\`\`

### 4. View Dashboard
Open browser: http://localhost:8000/dashboard/

## Tutorial: Your First Detection

1. **Explore existing detectors:**
\`\`\`bash
ls src/defense_evasion/
ls src/discovery/
\`\`\`

2. **Create a simple test:**
\`\`\`python
# test_detection.py
from src.defense_evasion.obfuscation_detector import T1027ObfuscationDetector

detector = T1027ObfuscationDetector()
test_data = {
    'file_path': 'suspicious.exe',
    'entropy_score': 7.5,
    'file_size': 1048576
}

result = detector.analyze(test_data)
print(f"Detection: {result}")
\`\`\`

3. **Run the test:**
\`\`\`bash
python test_detection.py
\`\`\`

## Next Steps
- Check out the tutorials in \`docs/tutorials/\`
- Review MITRE ATT&CK techniques covered
- Try building your own detector
- Explore the API documentation

## Need Help?
- Check \`docs/\` directory
- Review GitHub Issues
- Open a Discussion for questions
