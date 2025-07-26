# 🛡️ DriftBuddy

**AI-Powered Infrastructure Security Scanner with Intelligent Explanations**

DriftBuddy is a powerful security tool that combines [KICS](https://kics.io/) (Keeping Infrastructure as Code Secure) with AI-powered explanations to help developers identify and fix security misconfigurations in their Infrastructure as Code (IaC).

## ✨ Features

### 🔍 **Comprehensive Security Scanning**
- **Multi-format Support**: Scan Terraform, CloudFormation, Kubernetes, Docker, and more
- **500+ Security Rules**: Built on KICS's extensive security rule library
- **Real-time Analysis**: Instant feedback on security vulnerabilities

### 🤖 **AI-Powered Explanations**
- **Intelligent Context**: AI explains each finding in plain English
- **Actionable Fixes**: Provides secure code examples for each issue
- **Learning Resource**: Links to official documentation for deeper understanding

### 📊 **Beautiful Reporting**
- **HTML Dashboard**: Modern, interactive dashboard with severity-based grouping
- **Markdown Reports**: Clean, structured reports for documentation
- **Multiple Formats**: Generate HTML, Markdown, or both simultaneously

### 🎯 **Developer-Friendly CLI**
- **Simple Commands**: Easy-to-use command line interface
- **Flexible Output**: Choose your preferred report format
- **Progress Feedback**: Clear status updates during scanning

## 🚀 Quick Start

### Prerequisites

1. **Python 3.8+**
2. **KICS** - Download from [kics.io](https://kics.io/)
3. **OpenAI API Key** - Get from [OpenAI Platform](https://platform.openai.com/)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/driftbuddy.git
   cd driftbuddy
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your OpenAI API key**
   ```bash
   # Create .env file
   echo "OPENAI_API_KEY=your_api_key_here" > .env
   ```

4. **Download KICS** (if not already installed)
   ```bash
   # For Windows
   curl -L https://github.com/Checkmarx/kics/releases/latest/download/kics_windows_amd64.exe -o kics.exe
   
   # For macOS
   curl -L https://github.com/Checkmarx/kics/releases/latest/download/kics_darwin_amd64 -o kics
   chmod +x kics
   
   # For Linux
   curl -L https://github.com/Checkmarx/kics/releases/latest/download/kics_linux_amd64 -o kics
   chmod +x kics
   ```

## 📖 Usage

### Basic Scanning

```bash
# Scan a directory (generates markdown report by default)
python driftbuddy.py ./terraform-code

# Scan with HTML dashboard
python driftbuddy.py ./terraform-code --html

# Generate enhanced markdown report
python driftbuddy.py ./terraform-code --md

# Generate both HTML and markdown reports
python driftbuddy.py ./terraform-code --all
```

### Advanced Options

```bash
# Custom output directory for KICS results
python driftbuddy.py ./terraform-code --html --output-dir ./my-results

# Show version information
python driftbuddy.py --version

# Show help
python driftbuddy.py --help
```

### Command Line Options

| Flag | Description | Example |
|------|-------------|---------|
| `--html` | Generate beautiful HTML dashboard | `--html` |
| `--md` | Generate enhanced markdown report | `--md` |
| `--all` | Generate both HTML and markdown | `--all` |
| `--output-dir` | Custom output directory | `--output-dir ./results` |
| `--version` | Show version information | `--version` |
| `--help` | Show help and examples | `--help` |

## 📊 Report Formats

### HTML Dashboard
- **Modern Design**: Beautiful gradient background with card-based layout
- **Severity Grouping**: Findings organized by CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Interactive Elements**: Hover effects, smooth animations, and responsive design
- **Sticky Navigation**: Table of contents for easy browsing
- **Color-Coded Badges**: Red (Critical), Orange (High), Blue (Medium), Green (Low)

### Markdown Report
- **Structured Format**: Clean, readable markdown with proper headings
- **Severity Organization**: Findings grouped by security level
- **AI Explanations**: Detailed explanations and fixes for each finding
- **Documentation Links**: Direct links to official documentation
- **Summary Statistics**: Overview of findings by severity

## 🔍 Supported Infrastructure Formats

DriftBuddy supports scanning of various Infrastructure as Code formats:

- **Terraform** (`.tf`, `.tfvars`)
- **AWS CloudFormation** (`.yaml`, `.yml`, `.json`)
- **Kubernetes** (`.yaml`, `.yml`)
- **Docker** (`Dockerfile`, `docker-compose.yml`)
- **Azure Resource Manager** (`.json`)
- **Google Cloud Platform** (`.yaml`, `.yml`)
- **Ansible** (`.yml`, `.yaml`)
- **OpenAPI** (`.yaml`, `.yml`, `.json`)

## 🎯 Security Severity Levels

DriftBuddy categorizes findings into five severity levels:

| Level | Color | Description |
|-------|-------|-------------|
| **CRITICAL** | 🔴 Red | Immediate security risk requiring urgent attention |
| **HIGH** | 🟠 Orange | Significant security vulnerability |
| **MEDIUM** | 🔵 Blue | Moderate security concern |
| **LOW** | 🟢 Green | Minor security issue |
| **INFO** | ⚪ Gray | Informational finding |

## 📁 Project Structure

```
driftbuddy/
├── agent/
│   └── explainer.py          # AI explanation engine
├── test_data/
│   ├── iac_example/          # Sample Terraform code
│   └── output/               # KICS scan results
├── driftbuddy.py             # Main CLI application
├── drift_report.md           # Generated markdown report
├── kics_explained.html       # Generated HTML dashboard
└── README.md                 # This file
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
OPENAI_API_KEY=your_openai_api_key_here
```

### KICS Configuration

DriftBuddy uses KICS for security scanning. Ensure KICS is properly installed and accessible in your PATH.

## 🧪 Examples

### Example 1: Basic Terraform Scan

```bash
# Scan a Terraform directory
python driftbuddy.py ./my-terraform-project --html

# This will:
# 1. Run KICS scan on your Terraform files
# 2. Generate AI explanations for each finding
# 3. Create a beautiful HTML dashboard
# 4. Save results as kics_explained.html
```

### Example 2: Comprehensive Report

```bash
# Generate both HTML and markdown reports
python driftbuddy.py ./my-terraform-project --all

# This will create:
# - kics_explained.html (interactive dashboard)
# - drift_report.md (structured markdown report)
```

### Example Output

After running a scan, you'll see output like:

```
🚀 Starting DriftBuddy Security Scan...
📁 Scanning: ./terraform-code
📊 Reports: HTML + Markdown
--------------------------------------------------
🔍 Running KICS scan on: ./terraform-code
✅ KICS scan completed. Results saved to: test_data/output/results.json
🔍 Found 4 security issues to analyze...
🧠 Sending prompt for: S3 Bucket ACL Allows Read Or Write to All Users
📘 Response: [AI explanation of the issue and fix]
🎨 Generating HTML dashboard...
📝 Generating markdown report...
📊 HTML dashboard generated: kics_explained.html
📄 Markdown report generated: drift_report.md

🎉 Scan completed successfully!
💡 Open kics_explained.html in your browser to view the dashboard
💡 View drift_report.md for detailed findings
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Setup

```bash
# Clone and setup
git clone https://github.com/yourusername/driftbuddy.git
cd driftbuddy

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your OpenAI API key

# Run tests
python -m pytest tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **KICS Team**: For the excellent security scanning engine
- **OpenAI**: For providing the AI capabilities
- **Community**: For feedback and contributions

---

**Made with ❤️ for the DevOps community**
