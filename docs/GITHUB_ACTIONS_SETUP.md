# 🔄 DriftBuddy GitHub Actions Setup Guide

This guide will help you quickly integrate DriftBuddy into your GitHub repository for automated security scanning.

## 🚀 Quick Setup (3 Steps)

### Step 1: Add Workflow Files

Copy one of these workflows to your repository:

#### Option A: Basic Workflow
```bash
# Create the workflows directory
mkdir -p .github/workflows

# Copy the basic workflow
curl -o .github/workflows/driftbuddy.yml https://raw.githubusercontent.com/your-repo/driftbuddy/main/.github/workflows/driftbuddy-basic.yml
```

#### Option B: Advanced Workflow
```bash
# Create the workflows directory
mkdir -p .github/workflows

# Copy the advanced workflow
curl -o .github/workflows/driftbuddy.yml https://raw.githubusercontent.com/your-repo/driftbuddy/main/.github/workflows/driftbuddy-scan.yml
```

### Step 2: Add OpenAI API Key

1. Go to your repository → **Settings** → **Secrets and variables** → **Actions**
2. Click **"New repository secret"**
3. Name: `OPENAI_API_KEY`
4. Value: Your OpenAI API key from [OpenAI Platform](https://platform.openai.com/)

### Step 3: Commit and Push

```bash
git add .github/workflows/
git commit -m "Add DriftBuddy security scanning workflow"
git push
```

## 📋 Workflow Options

### Basic Workflow
- **Triggers**: All pushes and PRs to main branch
- **Features**: Simple scanning of entire repository
- **Best for**: Quick setup, small projects

### Advanced Workflow
- **Triggers**: Only when IaC files change
- **Features**: PR comments, path filtering, manual dispatch
- **Best for**: Large projects, team collaboration

## 🔧 Customization

### Change Scan Paths
Edit `.github/workflows/driftbuddy.yml`:
```yaml
on:
  push:
    branches: [ main ]
    paths:
      - '**/*.tf'          # Terraform files
      - '**/*.yaml'        # Kubernetes/CloudFormation
      - '**/terraform/**'  # Custom directories
```

### Modify Report Formats
```yaml
- name: Run DriftBuddy Security Scan
  run: |
    python driftbuddy.py . --html --reports-dir ./security-reports
```

### Add Custom Branches
```yaml
on:
  push:
    branches: [ main, develop, feature/* ]
  pull_request:
    branches: [ main, develop ]
```

## 📊 What You'll Get

### Automatic Scanning
- Runs on every push/PR to main branch
- Scans all IaC files in your repository
- Generates HTML dashboard and markdown report

### PR Comments
When security issues are found, you'll see comments like:
```
🔍 DriftBuddy Security Scan Results

Total Findings: 3

⚠️ Security issues detected! Please review the detailed reports.

📊 Reports Generated:
- HTML Dashboard: Available in artifacts
- Markdown Report: Available in artifacts

💡 Next Steps:
1. Download the security reports from the artifacts
2. Review and address any security findings
3. Re-run the scan after fixes to verify resolution
```

### Artifacts
- Security reports uploaded as GitHub artifacts
- 30-day retention period
- Easy download and review

## 🛠️ Troubleshooting

### Workflow Not Running
- Check that the workflow file is in `.github/workflows/`
- Verify the file has `.yml` extension
- Ensure you've pushed to the correct branch

### Missing OpenAI API Key
- Go to repository Settings → Secrets and variables → Actions
- Add `OPENAI_API_KEY` secret
- Make sure the secret name matches exactly

### KICS Installation Issues
The workflow automatically installs KICS, but if you have issues:
```yaml
- name: Install KICS (Alternative)
  run: |
    docker pull checkmarx/kics:latest
    echo "USE_DOCKER_KICS=true" >> $GITHUB_ENV
```

## 📈 Advanced Features

### Manual Workflow Dispatch
1. Go to your repository → **Actions**
2. Select **"DriftBuddy Security Scan"**
3. Click **"Run workflow"**
4. Configure scan parameters

### Custom Scan Paths
```yaml
- name: Run DriftBuddy Security Scan
  run: |
    python driftbuddy.py ./terraform --all --reports-dir ./security-reports
```

### Multiple Environments
Create separate workflows for different environments:
```yaml
# .github/workflows/driftbuddy-staging.yml
name: DriftBuddy Staging Scan
on:
  push:
    branches: [ develop ]
    paths:
      - 'staging/**'

# .github/workflows/driftbuddy-production.yml
name: DriftBuddy Production Scan
on:
  push:
    branches: [ main ]
    paths:
      - 'production/**'
```

## 🎯 Best Practices

1. **Start with Basic Workflow**: Use the basic workflow first, then upgrade to advanced
2. **Set Up Secrets Early**: Add your OpenAI API key before first run
3. **Review Artifacts**: Download and review reports to understand findings
4. **Customize Paths**: Adjust path filters to match your project structure
5. **Monitor Usage**: Keep track of OpenAI API usage and costs

## 📞 Support

If you encounter issues:
1. Check the workflow logs in GitHub Actions
2. Verify your OpenAI API key is valid
3. Ensure your repository contains IaC files
4. Review the [main README](../README.md) for detailed documentation

---

**Happy scanning! 🛡️**
