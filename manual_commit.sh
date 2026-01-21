#!/bin/bash

echo "=== MANUAL COMMIT SCRIPT ==="
echo ""

# Stage all changes except large files
echo "1. Staging changes..."
git add .
git reset -- tools/ trufflehog.tar.gz 2>/dev/null || true

echo "2. Creating commit..."
git commit -m "feat: Release MITRE ATT&CK Lab v1.0.0

íº€ Complete MITRE ATT&CK Detection Framework
===========================================

Core Features:
- 7+ MITRE technique detectors across 3 tactics
- Modular Python architecture for easy extension
- State management with SQLite persistence
- Configurable alerting engine with test mode
- REST API with authentication and RBAC
- Comprehensive test suite with 15+ test files
- Compliance reporting framework
- SIEM integration capabilities

Educational Value:
- Hands-on learning for MITRE ATT&CK techniques
- Clear, documented code for security education
- Quick start guides and tutorials
- Community contribution guidelines

Professional Enhancements:
- Modern pyproject.toml packaging
- GitHub Actions CI/CD pipeline
- Docker support for containerized deployment
- Type hints and comprehensive documentation

Ready for:
- Security education and training
- Production detection engineering
- Community contributions and extensions
- Integration with existing security stacks

í³Š Project Stats:
- 60+ Python source files
- 15+ test files
- 3 MITRE tactics covered
- Modular plugin architecture
- Full API documentation

í¾¯ Target Audience:
- Security beginners learning detection
- Enthusiasts building custom security tools
- Professionals needing modular detection framework"

echo "3. Pushing to GitHub..."
git push origin main

echo ""
echo "âœ… COMMIT COMPLETE!"
