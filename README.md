# 🔒 DriftBuddy - Infrastructure Security Scanner with Business Risk Assessment

**Enterprise-ready infrastructure security scanner with AI-powered explanations and comprehensive business risk assessment.**

## 🚀 Features

### 🔍 **Security Scanning**
- **KICS Integration**: Advanced Infrastructure as Code security scanning
- **Multi-format Support**: Terraform, Kubernetes, Docker, CloudFormation, and more
- **Real-time Analysis**: Instant vulnerability detection and assessment

### 📊 **Business Risk Assessment**
- **Impact Analysis**: Evaluates potential business consequences
- **Likelihood Assessment**: Determines probability of exploitation
- **Risk Matrix**: Visual risk prioritization (Critical, High, Medium, Low, Minimal)
- **Cost Estimation**: Financial impact analysis of security findings
- **Remediation Priority**: Business-focused action recommendations

### 🤖 **AI-Powered Insights**
- **Intelligent Explanations**: Context-aware security issue descriptions
- **Business Context**: Explains technical findings in business terms
- **Specific Fixes**: Code-level remediation suggestions
- **Cost-Benefit Analysis**: Justifies security investments

### 📈 **Comprehensive Reporting**
- **Multiple Formats**: Markdown, HTML, and JSON reports
- **Risk Visualization**: Color-coded risk matrix and summaries
- **Executive Summary**: Business-focused security overview
- **Actionable Recommendations**: Prioritized remediation steps

## 🎯 **Business Value**

### **For Security Teams**
- Prioritize findings by business impact, not just technical severity
- Understand the "why" behind security recommendations
- Get specific, actionable fixes with business justification

### **For Business Stakeholders**
- See security findings in business terms (cost, reputation, compliance)
- Understand financial impact of security risks
- Make informed decisions about security investments

### **For Development Teams**
- Get clear, contextual explanations of security issues
- Receive specific code fixes with business context
- Understand the business impact of security decisions

## 📦 Installation

### **Prerequisites**
- Python 3.8+
- KICS (Keeping Infrastructure as Code Secure)

### **Quick Start**
```bash
# Clone the repository
git clone https://github.com/your-org/driftbuddy.git
cd driftbuddy

# Install dependencies
pip install -r requirements.txt

# Install KICS (if not already installed)
# Visit: https://kics.io/
```

### **API Key Setup**
```bash
# Option 1: Environment variable
export OPENAI_API_KEY="your-api-key-here"

# Option 2: .env file
echo "OPENAI_API_KEY=your-api-key-here" > .env

# Option 3: Interactive setup
make setup-api-key
```

## 🚀 Usage

### **Basic Scan**
```bash
# Scan infrastructure code
python driftbuddy.py --scan-path ./terraform

# With AI explanations and business risk assessment
python driftbuddy.py --scan-path ./terraform --enable-ai
```

### **Advanced Usage**
```bash
# Generate HTML report with business risk assessment
python driftbuddy.py --scan-path ./k8s --output-format html --enable-ai

# Generate JSON report for integration
python driftbuddy.py --scan-path ./docker --output-format json

# Custom output directory
python driftbuddy.py --scan-path ./cloudformation --output-dir ./reports
```

### **Docker Usage**
```bash
# Run with Docker
docker run -v $(pwd):/workspace driftbuddy/driftbuddy \
  --scan-path /workspace/terraform --enable-ai

# With Docker Compose
docker-compose up
```

## 📊 **Business Risk Assessment**

### **Risk Matrix**
DriftBuddy uses a comprehensive risk matrix that considers:

| Impact/Likelihood | Very High | High | Medium | Low | Very Low |
|------------------|-----------|------|--------|-----|----------|
| **Critical** | 🔴 Critical | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low |
| **High** | 🔴 Critical | 🟠 High | 🟠 High | 🟡 Medium | 🟢 Low |
| **Medium** | 🟠 High | 🟡 Medium | 🟡 Medium | �� Low | ⚪ Minimal |
| **Low** | 🟡 Medium | 🟢 Low | 🟢 Low | ⚪ Minimal | ⚪ Minimal |
| **Minimal** | 🟢 Low | ⚪ Minimal | ⚪ Minimal | ⚪ Minimal | ⚪ Minimal |

### **Business Context Examples**

#### **Critical Business Risk**
- **AWS S3 Public Access**: Data breach, regulatory fines, reputation damage
- **Database Public Access**: Complete data compromise, compliance violations
- **Terraform State Exposure**: Infrastructure compromise, credential theft

#### **High Business Risk**
- **IAM Password Access**: Account compromise, unauthorized access
- **Security Group Open Ports**: Network compromise, lateral movement
- **EC2 Public IP**: Direct attack surface, data breach

#### **Medium Business Risk**
- **Lambda Public Access**: Code execution, service disruption
- **Container Root User**: Container escape, host compromise
- **Missing Logging**: Compliance issues, audit failures

### **Financial Impact Analysis**
- **Cost Estimation**: Realistic cost ranges for incident response
- **Time to Fix**: Estimated remediation effort
- **Priority Recommendations**: Business-focused action plans

## 📋 **Output Examples**

### **Console Output**
```
🔍 DriftBuddy - Infrastructure Security Scanner
==================================================
🔍 Starting KICS infrastructure scan...
📁 Scanning path: ./terraform
✅ KICS scan completed successfully
📊 Found 15 security queries
🔍 Total findings: 8

🤖 Generating AI explanations and business risk assessment...
📊 Business Risk Summary:
   🔴 Critical: 2
   🟠 High: 3
   🟡 Medium: 2
   🟢 Low: 1
   ⚪ Minimal: 0
💰 Total Estimated Cost: $125,000

📝 Generating report...
✅ Markdown report generated: outputs/reports/driftbuddy_report_20250125_143022.md

🎉 Scan completed successfully!
📁 Report saved to: outputs/reports/driftbuddy_report_20250125_143022.md

🚨 CRITICAL BUSINESS RISK DETECTED!
   Immediate action required for critical findings.
```

### **Report Features**
- **Executive Summary**: Business-focused overview
- **Risk Matrix**: Visual risk assessment
- **Detailed Findings**: Technical and business context
- **AI Explanations**: Intelligent issue descriptions
- **Specific Fixes**: Code-level remediation
- **Cost Analysis**: Financial impact assessment
- **Action Plans**: Prioritized remediation steps

## 🔧 **Configuration**

### **Environment Variables**
```bash
# OpenAI Configuration
OPENAI_API_KEY=your-api-key
OPENAI_MODEL=gpt-4
OPENAI_MAX_TOKENS=2000

# KICS Configuration
KICS_PATH=/usr/local/bin/kics
KICS_QUERIES_PATH=/path/to/queries

# Output Configuration
OUTPUT_DIR=outputs/reports
ENABLE_AI_EXPLANATIONS=true

# Security Configuration
ENABLE_DEMO_MODE=false
DEMO_OPENAI_API_KEY=sk-demo-key
```

### **Configuration File**
Create a `.env` file in your project root:
```env
# OpenAI Settings
OPENAI_API_KEY=your-api-key-here
OPENAI_MODEL=gpt-4
OPENAI_MAX_TOKENS=2000

# Feature Flags
ENABLE_AI_EXPLANATIONS=true
ENABLE_BUSINESS_RISK_ASSESSMENT=true

# Output Settings
OUTPUT_DIR=outputs/reports
REPORT_FORMAT=markdown

# Security Settings
ENABLE_DEMO_MODE=false
```

## 🏗️ **Project Structure**

```
driftbuddy/
├── src/driftbuddy/
│   ├── core.py              # Main application logic
│   ├── config.py            # Configuration management
│   ├── risk_assessment.py   # Business risk assessment
│   └── exceptions.py        # Error handling
├── src/agent/
│   └── explainer.py         # AI explanation agent
├── scripts/
│   ├── setup_api_key.py     # API key setup
│   └── security_scan.py     # Security checks
├── outputs/
│   ├── reports/             # Generated reports
│   └── analysis/            # Analysis results
├── test_data/
│   └── iac_example/         # Test infrastructure
├── docs/                    # Documentation
├── tests/                   # Test suite
└── examples/                # Usage examples
```

## 🧪 **Testing**

### **Run Tests**
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/driftbuddy

# Run specific test
pytest tests/test_risk_assessment.py
```

### **Test Infrastructure**
```bash
# Test with sample infrastructure
python driftbuddy.py --scan-path ./test_data/iac_example --enable-ai
```

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**
```bash
# Clone and setup
git clone https://github.com/your-org/driftbuddy.git
cd driftbuddy

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Run tests
pytest
```

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 **Support**

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/driftbuddy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/driftbuddy/discussions)

## 🔄 **Changelog**

See [CHANGELOG.md](CHANGELOG.md) for a complete list of changes and version history.

---

**🔒 Secure your infrastructure with business intelligence.**
