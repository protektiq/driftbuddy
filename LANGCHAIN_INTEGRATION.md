# LangChain Integration for DriftBuddy

This document describes the LangChain integration that enhances DriftBuddy's KICS and Steampipe capabilities with advanced AI features.

## Overview

The LangChain integration provides:

- **Memory**: Context-aware analysis across multiple scans
- **Chains**: Multi-step reasoning for complex security analysis
- **Agents**: Autonomous security analysis with tool usage
- **RAG**: Retrieval-Augmented Generation for knowledge-based analysis
- **Enhanced Reporting**: Advanced AI-powered security reports

## Installation

### Prerequisites

1. Install LangChain dependencies:
```bash
pip install langchain>=0.1.0 langchain-openai>=0.1.0 langchain-community>=0.1.0 langchain-core>=0.1.0 langchain-text-splitters>=0.1.0
```

2. Ensure OpenAI API key is configured:
```bash
export OPENAI_API_KEY="your-api-key-here"
```

### Verification

Test the LangChain integration:
```bash
python test_langchain_integration.py
```

## Usage

### Basic Usage

Enable LangChain analysis with the `--enable-langchain` flag:

```bash
# Run with LangChain enhancement
python driftbuddy-cli.py --scan-path ./terraform/ --enable-langchain --enable-ai

# Run comprehensive analysis
python driftbuddy-cli.py --scan-path . --all --enable-langchain --enable-ai
```

### Advanced Usage

#### LangChain-Only Analysis

Run only LangChain analysis on existing results:

```bash
python driftbuddy-cli.py --langchain-only --reports-dir ./previous-results/
```

#### Knowledge Base Integration

Create and use a knowledge base for enhanced analysis:

```bash
python driftbuddy-cli.py --scan-path . --enable-langchain --knowledge-base
```

## Features

### 1. Enhanced KICS Analysis

LangChain enhances KICS results with:

- **Context-aware analysis**: Considers previous findings and patterns
- **Business impact assessment**: Detailed risk analysis with cost estimates
- **Remediation recommendations**: Specific, actionable fixes
- **Attack scenario analysis**: Realistic threat modeling

```python
from driftbuddy.langchain_integration import create_langchain_integration

langchain = create_langchain_integration()
enhanced_results = langchain.enhance_kics_analysis(kics_results)
```

### 2. Enhanced Steampipe Analysis

LangChain enhances Steampipe cloud findings with:

- **Cloud-specific context**: Provider-aware analysis
- **Infrastructure drift detection**: Comparison with IaC
- **Compliance assessment**: Regulatory requirement mapping
- **Cost optimization**: Resource efficiency recommendations

```python
enhanced_steampipe = langchain.enhance_steampipe_analysis(steampipe_results)
```

### 3. Autonomous Security Agent

The enhanced agent can:

- **Analyze multiple data sources**: KICS + Steampipe + custom data
- **Generate comprehensive reports**: Executive summaries with recommendations
- **Provide remediation code**: Specific fixes for each finding
- **Assess business impact**: Risk scoring and prioritization

```python
from driftbuddy.agent.enhanced_agent import create_enhanced_agent

agent = create_enhanced_agent()
comprehensive_analysis = agent.run_comprehensive_analysis(
    kics_results=kics_data,
    steampipe_results=steampipe_data
)
```

### 4. Knowledge Base Integration

Create specialized knowledge bases for:

- **Industry-specific compliance**: SOC2, HIPAA, PCI-DSS
- **Cloud provider best practices**: AWS, Azure, GCP
- **Security frameworks**: NIST, ISO 27001
- **Custom organizational policies**

```python
# Create knowledge base from documents
documents = [
    "SOC2 compliance requirements...",
    "AWS security best practices...",
    "NIST cybersecurity framework..."
]

agent.create_knowledge_base(documents)

# Query knowledge base
response = agent.query_knowledge_base("How to implement SOC2 controls?")
```

## Architecture

### Components

1. **DriftBuddyLangChain**: Core LangChain integration
   - LLM initialization and configuration
   - Chain creation and management
   - Memory and context handling

2. **EnhancedSecurityAgent**: Advanced security analysis
   - Multi-tool agent with specialized tools
   - Comprehensive analysis workflows
   - Report generation capabilities

3. **Specialized Tools**:
   - `KICSAnalysisTool`: KICS results enhancement
   - `SteampipeAnalysisTool`: Cloud findings analysis
   - `SecurityRecommendationTool`: Comprehensive recommendations

### Data Flow

```
KICS Results → LangChain Analysis → Enhanced Findings
     ↓
Steampipe Results → LangChain Analysis → Enhanced Cloud Analysis
     ↓
Combined Analysis → Autonomous Agent → Comprehensive Report
```

## Configuration

### Environment Variables

```bash
# Required
OPENAI_API_KEY=your-openai-api-key

# Optional
LANGCHAIN_TRACING_V2=true
LANGCHAIN_ENDPOINT=https://api.smith.langchain.com
LANGCHAIN_API_KEY=your-langchain-api-key
LANGCHAIN_PROJECT=driftbuddy-security
```

### Configuration Options

```python
config = {
    "openai_api_key": "your-key",
    "model": "gpt-4o",
    "temperature": 0,
    "max_tokens": 2000,
    "memory_enabled": True,
    "knowledge_base_enabled": True
}
```

## Examples

### Example 1: Basic KICS Enhancement

```python
from driftbuddy.core import run_langchain_kics_analysis

# Run KICS scan
kics_results = run_kics("./terraform/")

# Enhance with LangChain
enhanced_results = run_langchain_kics_analysis(kics_results)
```

### Example 2: Comprehensive Analysis

```python
from driftbuddy.core import run_enhanced_analysis_with_langchain

# Run comprehensive analysis
results = run_enhanced_analysis_with_langchain(
    kics_results=kics_data,
    steampipe_results=steampipe_data,
    enable_ai=True
)
```

### Example 3: Knowledge Base Query

```python
from driftbuddy.core import query_knowledge_base

# Query security knowledge base
response = query_knowledge_base(
    "What are the best practices for securing S3 buckets?"
)
print(response)
```

## Reports

### Enhanced HTML Reports

LangChain-enhanced reports include:

- **Executive Summary**: Business-focused overview
- **Risk Assessment**: Detailed risk scoring
- **Remediation Roadmap**: Prioritized fixes
- **Cost Analysis**: Implementation cost estimates
- **Compliance Mapping**: Regulatory requirement alignment

### JSON Reports

Structured data for integration with:

- **SIEM systems**: Security information and event management
- **GRC platforms**: Governance, risk, and compliance
- **Ticketing systems**: Jira, ServiceNow, etc.
- **Custom dashboards**: Grafana, Kibana, etc.

## Performance

### Optimization Tips

1. **Batch Processing**: Process multiple findings together
2. **Caching**: Cache analysis results for repeated queries
3. **Async Processing**: Use async methods for large datasets
4. **Memory Management**: Clear memory between large scans

### Monitoring

Monitor LangChain performance with:

```python
# Enable tracing
import os
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
os.environ["LANGCHAIN_API_KEY"] = "your-api-key"
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all LangChain dependencies are installed
2. **API Key Issues**: Verify OpenAI API key is set correctly
3. **Memory Issues**: Clear memory for large scans
4. **Timeout Errors**: Increase timeout for complex analysis

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Integration with Existing Workflows

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run DriftBuddy with LangChain
  run: |
    python driftbuddy-cli.py \
      --scan-path ./infrastructure/ \
      --enable-langchain \
      --enable-ai \
      --all
```

### Custom Scripts

```python
from driftbuddy.core import run_enhanced_analysis_with_langchain

def custom_security_workflow():
    # Run scans
    kics_results = run_kics("./terraform/")
    steampipe_results = run_steampipe_scan("aws")
    
    # Enhanced analysis
    enhanced_results = run_enhanced_analysis_with_langchain(
        kics_results=kics_results,
        steampipe_results=steampipe_results
    )
    
    # Custom processing
    process_results(enhanced_results)
```

## Future Enhancements

### Planned Features

1. **Multi-Model Support**: Claude, Gemini, local models
2. **Custom Knowledge Bases**: Industry-specific templates
3. **Advanced RAG**: Document retrieval and synthesis
4. **Real-time Analysis**: Streaming analysis capabilities
5. **Integration APIs**: REST API for external tools

### Contributing

To contribute to the LangChain integration:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Support

For issues with LangChain integration:

1. Check the troubleshooting section
2. Review the test script output
3. Verify dependencies and configuration
4. Open an issue with detailed error information

## License

The LangChain integration follows the same license as DriftBuddy. 
