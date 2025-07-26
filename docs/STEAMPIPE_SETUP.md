# ☁️ Steampipe Integration Setup Guide

This guide will help you set up Steampipe integration with DriftBuddy for cloud infrastructure scanning, drift detection, and shadow resource identification.

## 🚀 Quick Setup

### Step 1: Install Steampipe

#### **macOS/Linux:**
```bash
# Install Steampipe
curl -s -L https://steampipe.io/install.sh | sh

# Restart your shell or run:
source ~/.bashrc
```

#### **Windows:**
```bash
# Download from https://steampipe.io/downloads
# Or use Chocolatey:
choco install steampipe
```

#### **Verify Installation:**
```bash
steampipe --version
```

### Step 2: Install Cloud Provider Plugins

```bash
# Install AWS plugin
steampipe plugin install aws

# Install Azure plugin
steampipe plugin install azure

# Install GCP plugin
steampipe plugin install gcp

# Install Kubernetes plugin
steampipe plugin install kubernetes
```

### Step 3: Configure Cloud Credentials

#### **AWS Configuration:**
```bash
# Set up AWS credentials
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

#### **Azure Configuration:**
```bash
# Login to Azure
az login

# Set subscription
az account set --subscription "your-subscription-id"
```

#### **GCP Configuration:**
```bash
# Login to GCP
gcloud auth login

# Set project
gcloud config set project your-project-id
```

#### **Kubernetes Configuration:**
```bash
# Ensure kubectl is configured
kubectl config current-context
```

### Step 4: Test Steampipe Integration

```bash
# Test AWS plugin
steampipe query "SELECT name FROM aws_s3_bucket LIMIT 5"

# Test Azure plugin
steampipe query "SELECT name FROM azure_storage_account LIMIT 5"

# Test GCP plugin
steampipe query "SELECT name FROM gcp_storage_bucket LIMIT 5"
```

## 🔍 Using Steampipe with DriftBuddy

### Basic Cloud Scanning

```bash
# AWS Security Scan
python driftbuddy.py --cloud aws --scan-type security

# Azure Shadow Resources Scan
python driftbuddy.py --cloud azure --scan-type shadow

# GCP Drift Detection
python driftbuddy.py --cloud gcp --scan-type drift

# All AWS Scans
python driftbuddy.py --cloud aws --all-scans
```

### Combined IaC + Cloud Scanning

```bash
# Scan IaC files AND cloud infrastructure
python driftbuddy.py ./terraform-code --all --cloud aws --scan-type security
```

## 📊 Scan Types

### 1. Security Scan (`--scan-type security`)
Detects security misconfigurations in cloud infrastructure:

- **AWS**: Public S3 buckets, overly permissive IAM policies, open security groups
- **Azure**: Public storage accounts, insecure network security groups
- **GCP**: Public storage buckets, overly permissive IAM roles
- **Kubernetes**: Insecure pod configurations, exposed services

### 2. Shadow Resources Scan (`--scan-type shadow`)
Identifies unmanaged infrastructure resources:

- **Old Resources**: Resources created more than 30-90 days ago
- **Unused Resources**: Stopped instances, empty buckets
- **Manual Resources**: Resources not managed by IaC

### 3. Drift Detection (`--scan-type drift`)
Compares IaC with actual cloud infrastructure:

- **Missing Resources**: Resources in IaC but not in cloud
- **Extra Resources**: Resources in cloud but not in IaC
- **Configuration Drift**: Resources with different configurations

## 🔧 Advanced Configuration

### Custom Queries

You can extend the Steampipe integration with custom queries:

```python
# In steampipe_integration.py
def get_custom_queries(self) -> Dict[str, List[str]]:
    return {
        "aws": [
            "SELECT name, cost_center FROM aws_s3_bucket WHERE cost_center IS NULL",
            "SELECT name, backup_retention_period FROM aws_rds_db_instance WHERE backup_retention_period < 7"
        ]
    }
```

### Plugin Configuration

Create Steampipe configuration files:

```bash
# ~/.steampipe/config/aws.spc
connection "aws" {
  plugin = "aws"
  regions = ["us-east-1", "us-west-2"]
  max_retry_attempts = 10
  max_retry_delay = 60
}
```

### Environment-Specific Scanning

```bash
# Development environment
python driftbuddy.py --cloud aws --scan-type security --reports-dir ./dev-reports

# Production environment
python driftbuddy.py --cloud aws --all-scans --reports-dir ./prod-reports
```

## 📈 Generated Reports

### Security Scan Report
```
# 🔍 Steampipe Infrastructure Analysis Report

**Generated:** 2024-12-25 14:30:52
**Provider:** AWS

## 📊 Summary

### 🚨 Security Issues Found

- **Total Issues:** 15
- **Critical Issues:** 3
- **High Priority:** 8
- **Medium Priority:** 4

#### Detailed Security Issues:
- **Public S3 Bucket:** test-bucket-123 (Public access enabled)
- **Overly Permissive IAM:** admin-user (AdministratorAccess policy)
- **Open Security Group:** web-sg (0.0.0.0/0 access)

## 💡 Recommendations

1. **Secure Public Resources:** Review and secure all public resources
2. **IAM Principle of Least Privilege:** Reduce IAM permissions
3. **Network Security:** Close unnecessary ports and IP ranges
4. **Regular Audits:** Schedule monthly security audits
```

### Shadow Resources Report
```
# 🔍 Steampipe Infrastructure Analysis Report

**Generated:** 2024-12-25 14:30:52
**Provider:** AWS

## 📊 Summary

### 👻 Shadow Resources

- **Total Shadow Resources:** 8
- **Resources Found:** 8

#### Detailed Shadow Resources:
- **old-test-bucket** (Created: 2024-09-15)
- **dev-instance-001** (Created: 2024-11-20)
- **temp-user-123** (Created: 2024-10-10)

## 💡 Recommendations

1. **Review Shadow Resources:** Investigate and document all shadow resources
2. **Implement IaC:** Convert shadow resources to Infrastructure as Code
3. **Regular Audits:** Schedule regular infrastructure audits
4. **Access Control:** Review and restrict access to prevent future shadow resources
```

## 🛠️ Troubleshooting

### Common Issues

#### **Steampipe Not Found**
```bash
# Check installation
which steampipe

# Reinstall if needed
curl -s -L https://steampipe.io/install.sh | sh
```

#### **Plugin Installation Failed**
```bash
# Check plugin status
steampipe plugin list

# Reinstall plugin
steampipe plugin uninstall aws
steampipe plugin install aws
```

#### **Authentication Errors**
```bash
# AWS
aws sts get-caller-identity

# Azure
az account show

# GCP
gcloud auth list
```

#### **Permission Errors**
```bash
# Check IAM permissions
steampipe query "SELECT arn, attached_policies FROM aws_iam_user WHERE name = 'current-user'"
```

### Performance Optimization

#### **Query Timeouts**
```bash
# Increase timeout in steampipe_integration.py
timeout=600  # 10 minutes instead of 5
```

#### **Large Infrastructure**
```bash
# Use pagination for large datasets
steampipe query "SELECT name FROM aws_s3_bucket LIMIT 100"
```

## 🔒 Security Best Practices

### 1. Credential Management
- Use IAM roles instead of access keys when possible
- Rotate credentials regularly
- Use least privilege access

### 2. Query Security
- Review all queries before running
- Test queries in non-production environments
- Monitor query costs and usage

### 3. Report Security
- Store reports securely
- Don't commit reports with sensitive data
- Use encryption for report storage

## 📚 Additional Resources

- **Steampipe Documentation:** https://steampipe.io/docs
- **Plugin Documentation:** https://hub.steampipe.io/plugins
- **Query Examples:** https://hub.steampipe.io/plugins/turbot/aws/tables
- **Community:** https://github.com/turbot/steampipe

---

**Happy cloud scanning! ☁️🔍** 