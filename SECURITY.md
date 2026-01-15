# Security Policy

This document outlines the security policies and procedures for the MITRE ATT&CK Python Lab project.

## Reporting a Vulnerability

To report a vulnerability, please open a [GitHub issue](https://github.com/Adrian-Obungu/mitre-attack-python-lab/issues) with a detailed description of the vulnerability and steps to reproduce it.

## Automated Security Pipeline

This project uses an automated security pipeline to prevent security regressions and proactively identify vulnerabilities. The pipeline consists of pre-commit hooks, a CI/CD security workflow, and automated dependency management.

### Pre-commit Hooks

We use `pre-commit` to run a series of checks before each commit. These hooks help catch issues early and maintain code quality. The following hooks are configured:

*   **Bandit**: Scans for common security issues in Python code. It runs on staged Python files and will fail on high-severity issues.
*   **Safety**: Checks for known vulnerabilities in Python dependencies. This hook runs only when `requirements.txt` or `config/requirements.txt` are modified.
*   **TruffleHog**: Scans for secrets and credentials in staged files.

To use the pre-commit hooks, you need to have `pre-commit` installed:

```bash
pip install pre-commit
```

Then, install the hooks into your local git repository:

```bash
pre-commit install
```

Now, the hooks will run automatically on every `git commit`.

### Local Security Scan Script

A local security scan script is available at `scripts/security_scan.sh`. This script mirrors the security checks performed in the CI/CD pipeline and can be run by developers to validate their changes locally before pushing.

To run the script:

```bash
./scripts/security_scan.sh
```

The script will:
1.  Run a full `bandit` scan on the `src/` directory for high-severity issues.
2.  Run a full `safety` scan on all `requirements.txt` files.
3.  Build all Docker images to ensure they are buildable.
4.  Run a basic API test to ensure the API server is functional.

### CI/CD Security Workflow

A GitHub Actions workflow is configured in `.github/workflows/security-scan.yml` to run on every push and pull request to the `main` branch. This workflow executes the same steps as the local security scan script, providing an additional layer of automated security verification.

### Dependency Management with Dependabot

We use Dependabot to automatically check for and create pull requests for vulnerable dependencies. The configuration is in `.github/dependabot.yml` and it scans for outdated Python and GitHub Actions dependencies weekly. Developers are encouraged to review and merge these pull requests promptly to keep the project's dependencies up-to-date and secure.
