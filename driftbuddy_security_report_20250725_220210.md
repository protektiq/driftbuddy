# 🧾 DriftBuddy Security Scan Report

**Generated:** 2025-07-25 22:02:10

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
1. Explanation: This security issue means that the Amazon S3 bucket, which is a storage resource in Amazon Web Services (AWS), is currently configured to allow any user to read (access) or write (modify) the data it contains. This is specified in the infrastructure as code (IaC) file "main.tf" at line 3.

2. Security Concern: This is a critical security concern because it means that anyone on the internet can access or modify the data in the S3 bucket. This can lead to data breaches, unauthorized changes, or even deletion of the data.

3. Secure Code Example:
   The following Terraform code example shows how to restrict access to the S3 bucket to only specific AWS accounts:

   ```hcl
   resource "aws_s3_bucket" "b" {
     bucket = "bucket-name"
     acl    = "private"

     policy = <<POLICY
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::ACCOUNT_ID:root"
         },
         "Action": "s3:*",
         "Resource": "arn:aws:s3:::bucket-name/*"
       }
     ]
   }
   POLICY
   }
   ```
   Replace "ACCOUNT_ID" with the AWS account ID that should have access, and "bucket-name" with the name of your S3 bucket.

4. Best Practices: 
   - Always use the least privilege principle when setting access controls. Only grant access to those who need it.
   - Regularly review and update your access controls.
   - Avoid hardcoding sensitive data like AWS account IDs in your IaC files. Use a secure method to store and retrieve these values.
   - Use automated tools to scan your IaC files for security issues before deployment.
   - Implement a strong policy for managing and rotating access keys.

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
This security issue is about a configuration setting in Amazon's S3 service. S3 is a storage service where you can store files, images, backups, etc. The issue is that Server Access Logging is not enabled for an S3 bucket. This means that any actions performed on this bucket (like uploading, deleting, or accessing files) are not being recorded.

2. Security Concern:
Without logging, it's impossible to track who did what and when. If a security breach occurs, such as unauthorized data access or data deletion, it would be very difficult to investigate without logs. This lack of accountability and traceability is a significant security risk.

3. Code Fix:
In your Terraform file (main.tf), you can enable logging by adding a `logging` block inside your `aws_s3_bucket` resource:

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
In this example, `target_bucket` is the name of another S3 bucket where you want to store the logs. `target_prefix` is a prefix added to the log file names.

4. Best Practices:
- Always enable access logging for your S3 buckets. It's a good practice to store logs in a separate, secure bucket.
- Regularly review your logs to detect any suspicious activity.
- Implement alerts for unusual activities like multiple failed login attempts or access from unusual locations.
- Limit access to your S3 buckets using IAM policies and make sure to follow the principle of least privilege (only give necessary permissions).
- Regularly update your IaC scripts to incorporate security best practices and updates.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)

---

### 🔍 S3 Bucket Without Versioning
**Severity:** MEDIUM

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** S3 bucket should have versioning enabled

**Explanation & Fix:**
1. Explanation:
The security issue 'S3 Bucket Without Versioning' means that the Amazon S3 bucket, defined in your Infrastructure as Code (IaC) file, does not have versioning enabled. Versioning is a feature that keeps multiple variants of an object in the same bucket. Without versioning, if objects are added, deleted, or modified in the bucket, you cannot retrieve previous versions of those objects.

2. Security Concern:
Not enabling versioning on an S3 bucket is a security concern because it can lead to data loss or corruption. If a file is accidentally deleted or overwritten, without versioning, there is no way to recover the previous version. This can be particularly problematic if a malicious actor gains access to the bucket and alters or deletes important data.

3. Secure Code Example:
Here's how you can enable versioning in your Terraform IaC file:

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "bucket-name"
  acl    = "private"

  versioning {
    enabled = true
  }
}
```
In this example, the `versioning` block with `enabled = true` ensures that versioning is turned on for the S3 bucket.

4. Best Practices:
To prevent this issue, always enable versioning on your S3 buckets. This can be done by adding a `versioning` block with `enabled = true` in your IaC file for each S3 bucket. Additionally, regularly review your IaC files to ensure that versioning is enabled on all existing S3 buckets. Lastly, consider using automated tools to scan your IaC files for security issues like this one.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning)

---

## LOW Findings (1)

### 🔍 IAM Access Analyzer Not Enabled
**Severity:** LOW

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** IAM Access Analyzer should be enabled and configured to continuously monitor resource permissions

**Explanation & Fix:**
1. Explanation: The IAM Access Analyzer is a feature in AWS that helps you identify resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an entity outside of your account. In this case, the Access Analyzer is not enabled in your Infrastructure as Code (IaC) configuration, which means your resources are not being continuously monitored for any unwanted or unexpected permissions.

2. Security Concern: If the IAM Access Analyzer is not enabled, you might not be aware of resources that are shared with external entities. This could potentially lead to unauthorized access or data breaches if these resources contain sensitive information.

3. Secure Code Example: You can enable the IAM Access Analyzer in your IaC configuration using Terraform. Here is an example:

```hcl
resource "aws_accessanalyzer_analyzer" "example" {
  analyzer_name = "example"
  type          = "ACCOUNT"
}
```

This code creates an Access Analyzer named 'example' for your account.

4. Best Practices: To prevent this issue, always enable IAM Access Analyzer in your AWS accounts. Regularly review the findings from the Access Analyzer and take appropriate actions to secure your resources. Incorporate this into your IaC configurations to ensure it's enabled by default. Also, consider using automated tools to check your IaC configurations for such issues.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/accessanalyzer_analyzer)

---

