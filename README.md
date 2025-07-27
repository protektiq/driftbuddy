# 🔒 DriftBuddy - Infrastructure Security Scanner with Business Risk Assessment

**Enterprise-ready infrastructure security scanner with AI-powered explanations and comprehensive business risk assessment using Impact × Likelihood methodology.**

## 🚀 Features

### 🔍 **Security Scanning**
- **KICS Integration**: Advanced Infrastructure as Code security scanning
- **Multi-format Support**: Terraform, Kubernetes, Docker, CloudFormation, and more
- **Real-time Analysis**: Instant vulnerability detection and assessment
- **Performance Optimized**: Parallel processing with configurable concurrency
- **Clean Branding**: DriftBuddy-branded output with custom ASCII art logo

### 📊 **Business Risk Assessment**
- **Impact × Likelihood Methodology**: Scientific risk calculation (1-25 scale)
- **Impact Analysis**: Evaluates potential business consequences (1-5 scale)
- **Likelihood Assessment**: Determines probability of exploitation (1-5 scale)
- **Risk Matrix**: Visual risk prioritization (Critical, High, Medium, Low, Minimal)
- **Cost Estimation**: Financial impact analysis with realistic cost ranges
- **Remediation Priority**: Business-focused action recommendations
- **Time-to-Fix Estimates**: Practical remediation timelines

### 🤖 **AI-Powered Insights**
- **Intelligent Explanations**: Context-aware security issue descriptions
- **Business Context**: Explains technical findings in business terms
- **Specific Fixes**: Code-level remediation suggestions with example code
- **Cost-Benefit Analysis**: Justifies security investments
- **Performance Optimized**: Batch processing with concurrent API calls
- **Deterministic Output**: Consistent AI responses with temperature=0

### 📈 **Comprehensive Reporting**
- **Multiple Formats**: HTML, Markdown, and JSON reports
- **Risk Visualization**: Color-coded risk matrix and summaries
- **Executive Summary**: Business-focused security overview
- **Actionable Recommendations**: Prioritized remediation steps
- **Financial Impact Dashboard**: Total cost analysis and breakdown
- **Embedded AI Analysis**: AI explanations and remediation code in main report

## 🎯 **Business Value**

### **For Security Teams**
- Prioritize findings by business impact, not just technical severity
- Understand the "why" behind security recommendations
- Get specific, actionable fixes with business justification
- See realistic cost estimates for incident response

### **For Business Stakeholders**
- See security findings in business terms (cost, reputation, compliance)
- Understand financial impact of security risks with detailed cost breakdowns
- Make informed decisions about security investments
- Get executive-level risk summaries

### **For Development Teams**
- Get clear, contextual explanations of security issues
- Receive specific code fixes with business context
- Understand the business impact of security decisions
- See realistic time-to-fix estimates

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
python driftbuddy.py --scan-path ./cloudformation --reports-dir ./reports

# Run all available scans (KICS + Steampipe if available)
python driftbuddy.py --scan-path . --all --enable-ai

# Test functionality only
python driftbuddy.py --test
```

### **Command Line Options**
```bash
python driftbuddy.py [OPTIONS]

Options:
  --scan-path PATH        Path to scan for infrastructure files (default: current directory)
  --output-format FORMAT  Output format: html, md, json, all (default: html)
  --enable-ai            Enable AI-powered analysis and recommendations
  --reports-dir DIR      Directory to save reports (default: outputs/reports)
  --all                  Run all available scans (KICS + Steampipe if available)
  --kics-only            Run only KICS scan
  --steampipe-only       Run only Steampipe scan (requires cloud credentials)
  --cloud-provider PROVIDER  Cloud provider for Steampipe scans: aws, azure, gcp (default: aws)
  --test                 Run functionality test only
```

### **Performance Configuration**
```bash
# Configure AI performance settings
export AI_MAX_CONCURRENT_REQUESTS=3
export AI_REQUEST_TIMEOUT=60
export AI_BATCH_SIZE=5
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

### **Risk Calculation Methodology**
DriftBuddy uses a scientific **Impact × Likelihood** methodology:

**Risk Score = Impact Level (1-5) × Likelihood Level (1-5) = 1-25**

| Risk Score | Risk Level | Description |
|------------|------------|-------------|
| 20-25 | 🔴 **Critical** | Immediate action required |
| 15-19 | 🟠 **High** | High priority remediation |
| 10-14 | 🟡 **Medium** | Moderate priority |
| 5-9 | 🟢 **Low** | Low priority |
| 1-4 | ⚪ **Minimal** | Acceptable risk |

### **Impact Levels (1-5 Scale)**
- **5 - Catastrophic**: Complete data breach, regulatory fines, reputation damage
- **4 - Major**: Significant business disruption, compliance violations
- **3 - Moderate**: Operational impact, audit failures
- **2 - Minor**: Limited business impact, configuration issues
- **1 - Insignificant**: Minimal business impact

### **Likelihood Levels (1-5 Scale)**
- **5 - Almost Certain**: High probability of exploitation
- **4 - Likely**: Probable exploitation under normal circumstances
- **3 - Possible**: Could occur under certain conditions
- **2 - Unlikely**: Low probability but possible
- **1 - Rare**: Very unlikely to occur

### **Business Context Examples**

#### **Critical Business Risk (Score 20-25)**
- **AWS S3 Public Access**: Data breach, regulatory fines, reputation damage
- **Database Public Access**: Complete data compromise, compliance violations
- **Terraform State Exposure**: Infrastructure compromise, credential theft

#### **High Business Risk (Score 15-19)**
- **IAM Password Access**: Account compromise, unauthorized access
- **Security Group Open Ports**: Network compromise, lateral movement
- **EC2 Public IP**: Direct attack surface, data breach

#### **Medium Business Risk (Score 10-14)**
- **Lambda Public Access**: Code execution, service disruption
- **Container Root User**: Container escape, host compromise
- **Missing Logging**: Compliance issues, audit failures

### **Financial Impact Analysis**
- **Cost Estimation**: Realistic cost ranges for incident response
- **Time to Fix**: Estimated remediation effort
- **Priority Recommendations**: Business-focused action plans
- **Total Cost Calculation**: Sum of all potential incident costs

## 📋 **Output Examples**

### **Console Output**
```
🔍 Starting DriftBuddy security scan...
📁 Scan path: /path/to/terraform
📊 Output format: html
🤖 AI analysis: Enabled

🔍 Running DriftBuddy security scan...
🔍 Starting DriftBuddy scan of: /path/to/terraform
✅ DriftBuddy engine found and accessible
💡 Using local DriftBuddy engine
🔍 Starting DriftBuddy local scan of: /path/to/terraform
🚀 Running DriftBuddy locally...

   ######                        ######                             
#     # #####  # ###### ##### #     # #    # #####  #####  #   # 
#     # #    # # #        #   #     # #    # #    # #    #  # #  
#     # #    # # #####    #   ######  #    # #    # #    #   #   
#     # #####  # #        #   #     # #    # #    # #    #   #   
#     # #   #  # #        #   #     # #    # #    # #    #   #   
######  #    # # #        #   ######   ####  #####  #####    #  
    🔍 Infrastructure Security Analysis Tool
    🛡️  Keeping Your Infrastructure as Code Secure

🔧 Running DriftBuddy engine command: kics scan -p /path/to/terraform -o outputs/reports --output-name kics_results_20250125_143022.json --report-formats json

Preparing DriftBuddy scan assets...
Executing queries: [---------------------------------------------------] 100.00%

✅ DriftBuddy scan completed - Found 4 findings
📊 Generating reports...
🤖 Running AI analysis...
🚀 Starting AI explanation generation...
📊 Total queries: 4
🔍 Queries with findings: 4
⚡ Using 3 concurrent workers
⏱️ Request timeout: 60s
✅ AI explanation generation completed in 12.45s
📈 Average time per query: 3.11s

✅ HTML report saved: outputs/reports/driftbuddy_security_report_20250125_143022.html
✅ Scan completed! Reports saved in: outputs/reports
```

### **HTML Report Features**
- **Executive Summary**: Business-focused overview with risk cards
- **Risk Matrix**: Visual risk assessment with Impact × Likelihood methodology
- **Financial Impact**: Total estimated cost of inaction with detailed breakdown
- **Detailed Findings**: Technical and business context for each issue
- **AI Explanations**: Intelligent issue descriptions with business context
- **Remediation Code**: Specific code examples to fix each issue
- **Action Plans**: Prioritized remediation steps with time estimates
- **Performance Metrics**: API call timing and optimization stats

## 🔧 **Configuration**

### **Environment Variables**
```bash
# OpenAI Configuration
OPENAI_API_KEY=your-api-key
OPENAI_MODEL=gpt-4o
OPENAI_MAX_TOKENS=1200

# AI Performance Settings
AI_MAX_CONCURRENT_REQUESTS=3
AI_REQUEST_TIMEOUT=60
AI_BATCH_SIZE=5

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
OPENAI_MODEL=gpt-4o
OPENAI_MAX_TOKENS=1200

# AI Performance Settings
AI_MAX_CONCURRENT_REQUESTS=3
AI_REQUEST_TIMEOUT=60
AI_BATCH_SIZE=5

# Feature Flags
ENABLE_AI_EXPLANATIONS=true
ENABLE_BUSINESS_RISK_ASSESSMENT=true

# Output Settings
OUTPUT_DIR=outputs/reports
REPORT_FORMAT=html

# Security Settings
ENABLE_DEMO_MODE=false
```

## 🏗️ **Project Structure**

```
driftbuddy/
├── src/driftbuddy/
│   ├── core.py              # Main application logic with CLI interface
│   ├── config.py            # Configuration management
│   ├── risk_assessment.py   # Business risk assessment (Impact × Likelihood)
│   └── exceptions.py        # Error handling
├── src/agent/
│   └── explainer.py         # AI explanation agent with remediation code
├── scripts/
│   ├── setup_api_key.py     # API key setup
│   ├── security_scan.py     # Security checks
│   └── test_performance.py  # Performance testing
├── outputs/
│   ├── reports/             # Generated reports
│   └── analysis/            # Analysis results
├── test_data/
│   └── iac_example/         # Test infrastructure
├── docs/                    # Documentation
│   └── PERFORMANCE_OPTIMIZATION.md
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

# Performance testing
python scripts/test_performance.py
```

### **Test Infrastructure**
```bash
# Test with sample infrastructure
python driftbuddy.py --scan-path ./test_data/iac_example --enable-ai

# Test risk calculation
python demo_risk_calculation.py

# Test functionality
python driftbuddy.py --test
```

## 🚀 **Performance Optimizations**

### **AI Processing Improvements**
- **Parallel Processing**: Concurrent API calls with ThreadPoolExecutor
- **Batch Processing**: Multiple findings per API call
- **Configurable Concurrency**: Adjustable worker count
- **Request Timeout**: Configurable timeout settings
- **Performance Monitoring**: Detailed timing metrics
- **Deterministic Output**: Consistent AI responses with temperature=0

### **Cost Calculation Enhancements**
- **Realistic Cost Ranges**: Industry-standard incident response costs
- **Vulnerability-Specific Estimates**: Different costs for different issue types
- **Total Cost Aggregation**: Sum of all potential incident costs
- **Cost Parsing**: Robust parsing of cost strings with descriptions

### **Report Generation**
- **Comprehensive HTML Reports**: Executive summary, risk matrix, financial impact
- **Embedded AI Analysis**: AI explanations and remediation code in main report
- **Clean Branding**: DriftBuddy ASCII art logo and consistent messaging
- **Filtered Output**: Removes KICS branding for clean DriftBuddy experience

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

# Test performance
python scripts/test_performance.py
```

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 **Support**

- **Documentation**: [docs/](docs/)
- **Performance Guide**: [docs/PERFORMANCE_OPTIMIZATION.md](docs/PERFORMANCE_OPTIMIZATION.md)
- **Issues**: [GitHub Issues](https://github.com/your-org/driftbuddy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/driftbuddy/discussions)

## 🔄 **Changelog**

See [CHANGELOG.md](CHANGELOG.md) for a complete list of changes and version history.

### **Recent Improvements**
- ✅ **CLI Interface**: Full command-line interface with argparse
- ✅ **HTML Report Generation**: Comprehensive reports with risk matrix and financial impact
- ✅ **AI-Powered Explanations**: Context-aware descriptions with remediation code
- ✅ **DriftBuddy Branding**: Custom ASCII art logo and consistent messaging
- ✅ **Impact × Likelihood Methodology**: Scientific risk calculation (1-25 scale)
- ✅ **Performance Optimizations**: Parallel processing and batch API calls
- ✅ **Cost Calculation**: Realistic financial impact analysis
- ✅ **Deterministic AI Output**: Consistent responses with temperature=0
- ✅ **Embedded AI Analysis**: AI explanations and code examples in main report
- ✅ **Error Handling**: Robust type checking and data validation

---

**🔒 Secure your infrastructure with business intelligence and scientific risk assessment.**
