#!/bin/bash

echo "=== Fixing GitHub Pages Build ==="

# 1. Create nojekyll file
echo "" > .nojekyll
echo "✅ Created .nojekyll"

# 2. Create proper workflow
mkdir -p .github/workflows
cat > .github/workflows/pages.yml << 'PAGESEOF'
name: Deploy Documentation

on:
  push:
    branches: [main]
    paths:
      - 'docs/**'
      - '.github/workflows/pages.yml'
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Setup Pages
        uses: actions/configure-pages@v4
      - name: Build with Jekyll (Simple)
        uses: actions/jekyll-build-pages@v1
        with:
          source: ./docs
          destination: ./_site
      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3

  deploy:
    environment:
      name: github-pages
      url: \${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    needs: build
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
PAGESEOF

echo "✅ Created custom GitHub Pages workflow"

# 3. Create a basic Jekyll config if docs/_config.yml doesn't exist
if [ ! -f docs/_config.yml ]; then
    cat > docs/_config.yml << 'CONFIGEOF'
title: "MITRE ATT&CK Python Lab"
description: "Documentation for cybersecurity project"
theme: jekyll-theme-minimal
baseurl: /mitre-attack-python-lab
CONFIGEOF
    echo "✅ Created docs/_config.yml"
fi

echo "=== Fix Applied ==="
echo "Commit and push these changes:"
echo "git add .nojekyll .github/workflows/pages.yml docs/_config.yml"
echo "git commit -m 'Fix GitHub Pages build'"
echo "git push origin main"
