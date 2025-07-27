#!/bin/bash

# DriftBuddy GitHub Actions Setup Script
# This script helps you set up DriftBuddy with GitHub Actions

set -e

echo "🚀 DriftBuddy GitHub Actions Setup"
echo "=================================="

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ Error: This script must be run from a git repository root"
    exit 1
fi

# Create .github/workflows directory
echo "📁 Creating GitHub Actions workflow directory..."
mkdir -p .github/workflows

# Copy the basic workflow
if [ ! -f ".github/workflows/driftbuddy-basic.yml" ]; then
    echo "📋 Copying basic workflow..."
    cp ../../.github/workflows/driftbuddy-basic.yml .github/workflows/
    echo "✅ Basic workflow copied to .github/workflows/driftbuddy-basic.yml"
else
    echo "⚠️  Basic workflow already exists"
fi

# Copy the advanced workflow
if [ ! -f ".github/workflows/driftbuddy-scan.yml" ]; then
    echo "📋 Copying advanced workflow..."
    cp ../../.github/workflows/driftbuddy-scan.yml .github/workflows/
    echo "✅ Advanced workflow copied to .github/workflows/driftbuddy-scan.yml"
else
    echo "⚠️  Advanced workflow already exists"
fi

# Check if requirements.txt exists
if [ ! -f "requirements.txt" ]; then
    echo "📝 Creating requirements.txt..."
    cat > requirements.txt << EOF
openai>=1.0.0
python-dotenv>=1.0.0
markdown>=3.4.0
EOF
    echo "✅ requirements.txt created"
else
    echo "✅ requirements.txt already exists"
fi

# Check if driftbuddy.py exists
if [ ! -f "driftbuddy.py" ]; then
    echo "❌ Error: driftbuddy.py not found in current directory"
    echo "💡 Please run this script from the directory containing driftbuddy.py"
    exit 1
fi

echo ""
echo "🎉 Setup Complete!"
echo ""
echo "📋 Next Steps:"
echo "1. Add your OpenAI API key to GitHub Secrets:"
echo "   - Go to your repository Settings > Secrets and variables > Actions"
echo "   - Add a new secret named 'OPENAI_API_KEY' with your API key"
echo ""
echo "2. Commit and push the changes:"
echo "   git add .github/workflows/ requirements.txt"
echo "   git commit -m 'Add DriftBuddy GitHub Actions workflows'"
echo "   git push"
echo ""
echo "3. The workflow will automatically run on:"
echo "   - Push to main branch"
echo "   - Pull requests to main branch"
echo "   - Manual trigger via GitHub Actions tab"
echo ""
echo "📊 Workflows Available:"
echo "   - driftbuddy-basic.yml: Simple scan on all pushes/PRs"
echo "   - driftbuddy-scan.yml: Advanced scan with path filtering and PR comments"
echo ""
echo "💡 To customize the workflow, edit .github/workflows/driftbuddy-scan.yml"
