# 🧾 DriftBuddy Security Scan Report

**Generated:** 2025-07-25 20:46:51

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
1. Explanation:
This issue means that the Amazon S3 bucket, which is a storage unit in the AWS cloud, is configured to allow any user to read or write data to it. This is not a secure configuration as it allows anyone, including potentially malicious users, to access or modify the data in the bucket.

2. Security Concern:
This is a critical security concern because it exposes sensitive data to unauthorized users. They can read, modify, or delete data, which can lead to data breaches, data loss, or malicious activities like ransomware attacks.

3. Secure Code Example:
Here is an example of how to fix this issue in your Terraform file (main.tf):

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "my-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }
}
```
In this example, the 'acl' (Access Control List) attribute is set to 'private'. This means that only the bucket owner and AWS services with explicit permissions can access the bucket.

4. Best Practices:
- Always set the 'acl' attribute of your S3 buckets to 'private' unless there is a specific need for public access.
- Regularly review and update your bucket permissions.
- Use AWS IAM (Identity and Access Management) to manage access to your S3 resources. IAM allows you to create and manage AWS users and groups and use permissions to allow and deny their access to AWS resources.
- Enable versioning on your S3 buckets to protect against accidental deletion or overwriting of data.
- Use encryption to protect your data at rest and in transit.
- Regularly audit your S3 buckets using tools like AWS Trusted Advisor or AWS Config to identify any public buckets and fix them.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)

---

## MEDIUM Findings (2)

### 🔍 S3 Bucket Logging Disabled
**Severity:** MEDIUM

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** Server Access Logging should be enabled on S3 Buckets so that all changes are logged and trackable

**Explanation & Fix:**
1. Explanation:
This security issue means that the S3 bucket in your Infrastructure as Code (IaC) setup does not have server access logging enabled. This means that any changes made to the bucket, such as data uploads, downloads, or deletions, are not being recorded.

2. Security Concern:
Without logging enabled, it's difficult to track and monitor activities performed on the S3 bucket. If an unauthorized user gains access and performs malicious activities, it would be challenging to identify what was done, when it was done, and by whom. This lack of visibility and traceability can lead to data breaches and other security incidents.

3. Secure Code Example:
To fix this issue, you need to enable server access logging for your S3 bucket in your Terraform file. Here's an example of how to do it:

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
In this example, `target_bucket` is the name of another S3 bucket where you want to store the logs, and `target_prefix` is the prefix added to the log file names.

4. Best Practices:
- Always enable server access logging for your S3 buckets.
- Regularly review your logs to identify any suspicious activities.
- Use a separate, secure S3 bucket to store your logs to prevent unauthorized access or accidental deletion.
- Implement alerts and monitoring systems to notify you of any unusual activities.
- Regularly update and review your IaC scripts to ensure they follow the latest security best practices.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)

---

### 🔍 S3 Bucket Without Versioning
**Severity:** MEDIUM

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** S3 bucket should have versioning enabled

**Explanation & Fix:**
1. Explanation: This security issue means that the Amazon S3 bucket defined in your Infrastructure as Code (IaC) file (main.tf) does not have versioning enabled. Versioning is a feature that keeps multiple variants of an object in the same bucket. Without versioning, you cannot preserve, retrieve, and restore every version of every object in your bucket, which can be a problem if a file is accidentally deleted or overwritten.

2. Security Concern: Not having versioning enabled is a security concern because it leaves your data vulnerable to accidental deletion or overwriting. If a malicious actor gains access to your S3 bucket, they could potentially delete or modify your data and without versioning, you would not be able to recover the original data. 

3. Secure Code Example: Here's how you can enable versioning in your Terraform file:

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "bucket-name"
  acl    = "private"

  versioning {
    enabled = true
  }
}
```

In this example, `versioning` block is added with `enabled = true` which turns on versioning for the S3 bucket.

4. Best Practices: To prevent this issue, always enable versioning for your S3 buckets. Make it a standard practice to include the versioning block in your Terraform configuration for S3 buckets. Additionally, regularly review your IaC files to ensure that versioning is enabled for all existing S3 buckets. Consider using automated tools to scan your IaC for such misconfigurations.

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
The IAM Access Analyzer is a feature in AWS that helps you identify resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an entity outside of your account. In this case, the Access Analyzer is not enabled in your Infrastructure as Code (IaC) configuration file, which means you might not be aware if your resources are shared with external entities.

2. Security Concern:
Not having the IAM Access Analyzer enabled is a security concern because it can lead to unauthorized access to your resources. If an external entity has access to your resources, they might be able to read, modify, or delete your data, which can lead to data breaches.

3. Secure Code Example:
To fix this issue, you need to enable the IAM Access Analyzer in your IaC configuration file. Below is an example of how to do this in Terraform:

```terraform
resource "aws_accessanalyzer_analyzer" "example" {
  analyzer_name = "example"
  type          = "ACCOUNT"
}
```
This code block creates an Access Analyzer for your account with the name "example".

4. Best Practices:
- Always enable IAM Access Analyzer in your AWS accounts to continuously monitor your resources.
- Regularly review the findings from the Access Analyzer and take appropriate actions.
- Follow the principle of least privilege when granting permissions. Only grant the minimum permissions necessary for a user or service to function.
- Regularly rotate and audit AWS credentials.
- Use AWS managed policies for job functions to assign permissions whenever possible.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/accessanalyzer_analyzer)

---

