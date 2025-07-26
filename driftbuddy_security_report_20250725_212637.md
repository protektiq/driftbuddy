# 🧾 DriftBuddy Security Scan Report

**Generated:** 2025-07-25 21:26:37

## 📊 Summary
**Total Findings:** 4

- **CRITICAL:** 1
- **MEDIUM:** 2
- **LOW:** 1

---

## CRITICAL Findings (1)

### 🔍 S3 Bucket ACL Allows Read Or Write to All Users
**Severity:** CRITICAL

**File:** `./test_data/iac_example/main.tf`  
**Line:** `3`  
**Description:** S3 Buckets should not be readable and writable to all users

**Explanation & Fix:**
1. Explanation: This security issue means that the Access Control List (ACL) settings for your Amazon S3 bucket, as defined in your Infrastructure as Code (IaC) file, are currently set to allow any user to read or write data to your bucket. This means anyone with internet access could potentially view, download, or modify the data stored in your S3 bucket.

2. Security Concern: This is a critical security concern because it exposes your data to potential unauthorized access and manipulation. Sensitive data could be stolen, or malicious data could be uploaded to your bucket. This could lead to data breaches, data corruption, and other serious security incidents.

3. Code Fix: To fix this issue, you need to change the ACL settings for your S3 bucket to restrict access. Here's an example using Terraform:

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "your_bucket_name"
  acl    = "private"

  versioning {
    enabled = true
  }
}
```
In this example, the `acl` attribute is set to `private`, which means only the bucket owner has access to the bucket.

4. Best Practices: To prevent this issue, always follow the principle of least privilege when setting access controls - only grant access to those who absolutely need it. Regularly review and update your ACL settings to ensure they're still appropriate for your needs. Also, consider using bucket policies or IAM policies for more granular control over bucket access. Lastly, use tools to automatically scan your IaC for security issues, and address any findings promptly.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)

---

## MEDIUM Findings (2)

### 🔍 S3 Bucket Logging Disabled
**Severity:** MEDIUM

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** Server Access Logging should be enabled on S3 Buckets so that all changes are logged and trackable

**Explanation & Fix:**
1. Explanation: This security issue means that your Amazon S3 bucket, which is a storage unit in Amazon's cloud storage service, does not have Server Access Logging enabled. Server Access Logging is a feature that records all requests made to your S3 bucket, providing a history of changes made to the bucket's data.

2. Security Concern: Without Server Access Logging, you won't have a record of who has accessed your S3 bucket or what changes they've made. This makes it difficult to track unauthorized access or modifications, which could lead to data breaches or loss. It also makes it harder to audit your system for compliance with security standards.

3. Code Fix: You can enable Server Access Logging in your Terraform code by adding a `logging` block to your `aws_s3_bucket` resource. Here's an example:

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "bucket-name"
  acl    = "private"

  logging {
    target_bucket = "logging-bucket-name"
    target_prefix = "log/"
  }
}
```
In this example, `target_bucket` is the name of another S3 bucket where you want to store the logs, and `target_prefix` is a prefix added to the log file names.

4. Best Practices: Always enable Server Access Logging for your S3 buckets. Store the logs in a separate, secure bucket that has strict access controls. Regularly review and monitor your logs for any suspicious activity. Use automated tools to analyze the logs and alert you to potential security issues. Ensure that your logging bucket has versioning enabled to prevent accidental deletion or modification of logs.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)

---

### 🔍 S3 Bucket Without Versioning
**Severity:** MEDIUM

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** S3 bucket should have versioning enabled

**Explanation & Fix:**
1. Explanation: This security issue means that the S3 bucket defined in your Infrastructure as Code (IaC) file (main.tf) does not have versioning enabled. Versioning is a feature in AWS S3 that keeps multiple versions of an object in the same bucket. Without versioning, if an object is deleted or overwritten, there's no way to restore it.

2. Security Concern: The absence of versioning can lead to data loss, either through accidental deletion or overwriting, or through malicious activity such as ransomware attacks. It also prevents the ability to track changes and roll back to a previous state if needed, which is a key aspect of maintaining data integrity and security.

3. Code Fix: Here's how you can enable versioning in your Terraform code:

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "bucket-name"
  acl    = "private"

  versioning {
    enabled = true
  }
}
```
In this code, the `versioning` block with `enabled = true` turns on versioning for the S3 bucket.

4. Best Practices: To prevent this issue, always enable versioning for S3 buckets in your IaC scripts. It's also a good practice to use lifecycle rules to manage noncurrent versions and prevent the bucket from becoming too large. Additionally, regularly review and update your IaC scripts to ensure they follow the latest security best practices. Automated tools can help identify potential security issues in your IaC scripts.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning)

---

## LOW Findings (1)

### 🔍 IAM Access Analyzer Not Enabled
**Severity:** LOW

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** IAM Access Analyzer should be enabled and configured to continuously monitor resource permissions

**Explanation & Fix:**
1. Explanation:
This issue means that the IAM Access Analyzer, a tool provided by AWS to help you identify resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an entity outside of your account, is not enabled in your Infrastructure as Code (IaC) configuration.

2. Security Concern:
Not having the IAM Access Analyzer enabled is a security concern because it means you are not continuously monitoring your resource permissions. This could potentially allow unauthorized access to your resources, leading to data breaches or other security incidents.

3. Secure Code Example:
To fix this issue, you need to enable the IAM Access Analyzer in your IaC configuration. Here is an example using Terraform:

```hcl
resource "aws_accessanalyzer_analyzer" "example" {
  analyzer_name = "example"
  type          = "ACCOUNT"
}
```
This code creates an IAM Access Analyzer for your account.

4. Best Practices:
To prevent this issue, always enable IAM Access Analyzer in your IaC configurations. Regularly review and update your IAM policies and permissions. Ensure that you follow the principle of least privilege, granting only necessary permissions to your resources. Regularly audit your configurations and use automated tools to detect any security issues.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/accessanalyzer_analyzer)

---

