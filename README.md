# 🛡️ DriftBuddy - AI-Powered Infrastructure Security Scanner

DriftBuddy is an intelligent security scanner that combines the power of KICS (Keeping Infrastructure as Code Secure) with OpenAI's GPT-4 to provide comprehensive, AI-enhanced security analysis for your Infrastructure as Code (IaC) files.

## ✨ Features

- **🔍 Comprehensive Scanning**: Supports Terraform, AWS CloudFormation, Kubernetes, Docker, Azure Bicep, and more
- **🤖 AI-Powered Explanations**: Uses OpenAI GPT-4 to provide detailed, actionable explanations for each security finding
- **📊 Beautiful Reports**: Generates both HTML dashboards and markdown reports with timestamped filenames
- **🔄 CI/CD Integration**: Ready-to-use GitHub Actions workflows for automated security scanning
- **🎯 Smart Filtering**: Focuses on relevant file types and provides intelligent path-based scanning
- **🛡️ Graceful Error Handling**: Robust error handling for missing dependencies, API issues, and invalid files

## 🚀 Quick Start

### Prerequisites

1. **Python 3.8+** installed on your system
2. **KICS** - Download from [kics.io](https://kics.io/) or use Docker
3. **OpenAI API Key** - Get one from [OpenAI Platform](https://platform.openai.com/)

### Installation

1. **Clone or download DriftBuddy**:
   ```bash
   git clone <repository-url>
   cd driftbuddy
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your OpenAI API key**:
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   # Or create a .env file:
   echo "OPENAI_API_KEY=your-api-key-here" > .env
   ```

4. **Install KICS** (choose one method):
   ```bash
   # Method 1: Download binary
   curl -L https://github.com/Checkmarx/kics/releases/latest/download/kics_linux_amd64.tar.gz -o kics.tar.gz
   tar -xzf kics.tar.gz
   sudo mv kics /usr/local/bin/
   
   # Method 2: Use Docker
   docker pull checkmarx/kics:latest
   ```

### Basic Usage

```bash
# Scan a directory
python driftbuddy.py ./terraform-code --all

# Scan a specific file
python driftbuddy.py ./main.tf --html

# Generate only markdown report
python driftbuddy.py ./terraform-code --md

# Save reports to custom directory
python driftbuddy.py ./terraform-code --all --reports-dir ./security-reports
```

## 🔄 GitHub Actions Integration

DriftBuddy includes ready-to-use GitHub Actions workflows for automated security scanning in your CI/CD pipeline.

### Quick Setup

1. **Run the setup script** (if you have DriftBuddy in your repository):
   ```bash
   bash scripts/setup-github-actions.sh
   ```

2. **Add your OpenAI API key to GitHub Secrets**:
   - Go to your repository → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `OPENAI_API_KEY`
   - Value: Your OpenAI API key

3. **Commit and push the changes**:
   ```bash
   git add .github/workflows/ requirements.txt
   git commit -m "Add DriftBuddy GitHub Actions workflows"
   git push
   ```

### Available Workflows

#### 1. Basic Workflow (`.github/workflows/driftbuddy-basic.yml`)
- **Triggers**: Push to main, Pull requests to main, Manual dispatch
- **Features**: Simple scanning of entire repository
- **Output**: Uploads security reports as artifacts

#### 2. Advanced Workflow (`.github/workflows/driftbuddy-scan.yml`)
- **Triggers**: Push/PR with IaC file changes, Manual dispatch with options
- **Features**: 
  - Path-based triggering (only runs when IaC files change)
  - PR comments with findings summary
  - Configurable scan paths and report formats
  - Detailed artifact uploads

### Manual Workflow Dispatch

You can manually trigger scans with custom parameters:

1. Go to your repository → Actions
2. Select "DriftBuddy Security Scan"
3. Click "Run workflow"
4. Configure:
   - **scan_path**: Directory to scan (default: `.`)
   - **report_format**: `all`, `html`, or `md`

### Workflow Features

#### Automatic PR Comments
When security issues are found in pull requests, the workflow automatically comments with:
- Summary of findings
- Links to detailed reports
- Actionable next steps

#### Smart Path Filtering
The advanced workflow only runs when relevant files change:
- `**/*.tf` (Terraform)
- `**/*.yaml`, `**/*.yml` (Kubernetes, CloudFormation)
- `**/*.json` (CloudFormation, ARM templates)
- `**/*.bicep` (Azure Bicep)
- `**/*.dockerfile`, `**/Dockerfile` (Docker)

#### Artifact Management
- Reports are uploaded as GitHub artifacts
- 30-day retention period
- Easy download and review

### Customizing Workflows

#### Modify Scan Paths
Edit `.github/workflows/driftbuddy-scan.yml`:
```yaml
on:
  push:
    branches: [ main, develop ]
    paths:
      - '**/*.tf'          # Add your file patterns
      - '**/*.yaml'
      - '**/terraform/**'   # Custom directories
```

#### Change Report Formats
Modify the scan command:
```yaml
- name: Run DriftBuddy Security Scan
  run: |
    python driftbuddy.py . --html --reports-dir ./security-reports
```

#### Add Custom Branches
```yaml
on:
  push:
    branches: [ main, develop, feature/* ]
  pull_request:
    branches: [ main, develop ]
```

### Example Workflow Output

```
🔍 DriftBuddy Security Scan Results

Total Findings: 5

⚠️ Security issues detected! Please review the detailed reports.

📊 Reports Generated:
- HTML Dashboard: Available in artifacts
- Markdown Report: Available in artifacts

💡 Next Steps:
1. Download the security reports from the artifacts
2. Review and address any security findings
3. Re-run the scan after fixes to verify resolution

🔗 View Reports: Check the "driftbuddy-security-reports" artifacts in this workflow run.
```

## 📊 Report Formats

### HTML Dashboard
- **File**: `driftbuddy_security_dashboard_YYYYMMDD_HHMMSS.html`
- **Features**: 
  - Interactive dashboard with severity grouping
  - Color-coded severity badges
  - Sticky table of contents
  - Responsive design
  - Summary cards with findings counts

### Markdown Report
- **File**: `driftbuddy_security_report_YYYYMMDD_HHMMSS.md`
- **Features**:
  - Detailed findings grouped by severity
  - AI-generated explanations and fixes
  - Links to official documentation
  - Timestamp and scan summary

## 🔍 Supported Infrastructure Formats

DriftBuddy supports scanning the following IaC formats:

| Format | Extensions | Examples |
|--------|------------|----------|
| **Terraform** | `.tf`, `.tfvars` | AWS, Azure, GCP resources |
| **Kubernetes** | `.yaml`, `.yml` | Pods, Services, ConfigMaps |
| **Docker** | `Dockerfile`, `.dockerfile` | Container configurations |
| **AWS CloudFormation** | `.yaml`, `.yml`, `.json` | AWS infrastructure |
| **Azure Bicep** | `.bicep` | Azure resources |
| **Google Cloud** | `.yaml`, `.yml` | GCP deployment manager |

## 🚨 Security Severity Levels

DriftBuddy categorizes findings by severity:

| Level | Color | Description |
|-------|-------|-------------|
| **CRITICAL** | 🔴 Red | Immediate security risks requiring urgent attention |
| **HIGH** | 🟠 Orange | Significant security vulnerabilities |
| **MEDIUM** | 🔵 Blue | Moderate security concerns |
| **LOW** | 🟢 Green | Minor security issues or best practices |
| **INFO** | ⚪ Gray | Informational findings |

## 📁 Project Structure

```
driftbuddy/
├── driftbuddy.py              # Main CLI application
├── agent/
│   └── explainer.py           # AI explanation engine
├── .github/
│   └── workflows/             # GitHub Actions workflows
│       ├── driftbuddy-basic.yml
│       └── driftbuddy-scan.yml
├── scripts/
│   ├── run_kics.sh           # Docker KICS runner
│   └── setup-github-actions.sh # GitHub Actions setup
├── test_data/
│   └── iac_example/          # Sample vulnerable IaC files
├── requirements.txt           # Python dependencies
└── README.md                 # This file
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `OPENAI_API_KEY` | Your OpenAI API key | Yes |
| `USE_DOCKER_KICS` | Use Docker KICS instead of local | No |

### Command Line Options

```bash
python driftbuddy.py [SCAN_PATH] [OPTIONS]

Options:
  --html              Generate HTML dashboard
  --md                Generate markdown report
  --all               Generate all report formats
  --output-dir DIR    KICS results directory (default: test_data/output)
  --reports-dir DIR   Reports output directory (default: current directory)
  --version           Show version information
```

## 🧪 Examples

### Example 1: Basic Terraform Scan
```bash
# Scan a Terraform directory
python driftbuddy.py ./terraform-infrastructure --all

# Output:
# 📊 HTML Dashboard: driftbuddy_security_dashboard_20241225_143052.html
# 📄 Markdown Report: driftbuddy_security_report_20241225_143052.md
```

### Example 2: Kubernetes Security Scan
```bash
# Scan Kubernetes manifests
python driftbuddy.py ./k8s-manifests --html --reports-dir ./security-reports

# Output:
# 📊 HTML Dashboard: ./security-reports/driftbuddy_security_dashboard_20241225_143052.html
```

### Example 3: GitHub Actions Integration
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run DriftBuddy
        run: |
          python driftbuddy.py . --all --reports-dir ./reports
```

## 🔧 Troubleshooting

### Common Issues

#### KICS Not Found
```bash
# Install KICS
curl -L https://github.com/Checkmarx/kics/releases/latest/download/kics_linux_amd64.tar.gz -o kics.tar.gz
tar -xzf kics.tar.gz
sudo mv kics /usr/local/bin/
```

#### OpenAI API Key Issues
```bash
# Set API key
export OPENAI_API_KEY="your-key-here"

# Or use .env file
echo "OPENAI_API_KEY=your-key-here" > .env
```

#### Docker KICS Alternative
```bash
# Use Docker if local KICS fails
docker run --rm -v $(pwd):/path checkmarx/kics:latest scan -p /path
```

### Error Messages

| Error | Solution |
|-------|----------|
| `KICS executable not found` | Install KICS or use Docker |
| `OPENAI_API_KEY not found` | Set your OpenAI API key |
| `No security issues found` | This is normal - your code is secure! |
| `Invalid scan path` | Check that the path exists and contains IaC files |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone the repository
git clone <repository-url>
cd driftbuddy

# Install dependencies
pip install -r requirements.txt

# Set up pre-commit hooks
pip install pre-commit
pre-commit install

# Run tests
python -m pytest tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **KICS** - The underlying security scanning engine
- **OpenAI** - For providing the AI explanation capabilities
- **GitHub Actions** - For the CI/CD integration framework

---

**Made with ❤️ for secure infrastructure**
