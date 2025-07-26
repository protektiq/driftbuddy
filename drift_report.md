# 🧾 DriftBuddy Security Scan Report

**Generated:** 2025-07-25 19:51:19

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
This issue is about potential data leakage in your Amazon S3 bucket. 

Amazon S3 is a service offered by Amazon Web Services for online object storage. An S3 bucket is like a directory where you can store your files or data. Advanced Configuration and Power Interface (ACPI) List (ACL) is one way to manage access to your buckets and objects. 

In the Terraform file written, the ACL of the S3 bucket is configured in such a way that every user, regardless of their permissions, can read or write in the bucket. This is considered extremely unsafe because confidential data may be exposed to unauthorized users, leading to data theft or loss.

The secure way to handle this is by restricting access to the S3 bucket. Only authorized IAM users should have access to sensitive data. 

The code fix would be to change the "acl" field's value to "private" instead of "public-read-write". A fixed sample code would be as follows:

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}
```

This code creates a private S3 bucket. By setting the ACL to "private", only the bucket owner can read and write the files unless explicit permission is given to other users.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)

---

## MEDIUM Findings (2)

### 🔍 S3 Bucket Logging Disabled
**Severity:** MEDIUM

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** Server Access Logging should be enabled on S3 Buckets so that all changes are logged and trackable

**Explanation & Fix:**
Issue:
This issue is about a configuration in Amazon Web Services (AWS) where an S3 (Simple Storage Service) bucket has not been set up to keep a log of all accesses and changes. This logging is important to help track any changes made to the bucket, providing an audit trail that can be useful for security and troubleshooting purposes.

Secure Terraform Code Fix:

Here is an example of how you can enable logging for your S3 buckets using Terraform:

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "my_bucket"
  acl    = "private"

  logging {
    target_bucket = "${aws_s3_bucket.log_bucket.id}"
    target_prefix = "log/"
  }
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "my_log_bucket"
  acl    = "log-delivery-write"
}
```

In this code, a new S3 bucket named "my_bucket" is created with access control list (ACL) configured as 'private'. This means the bucket is not publicly accessible. Next, logging is enabled for "my_bucket" with logs delivered to another S3 bucket named "my_log_bucket". The "target_prefix" specifies a prefix for the log file names. The "log-delivery-write" ACL for the "log_bucket" allows the log delivery group write access to the bucket, enabling the delivery of access logs to the bucket.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)

---

### 🔍 S3 Bucket Without Versioning
**Severity:** MEDIUM

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** S3 bucket should have versioning enabled

**Explanation & Fix:**
This issue is pointing out that in your Amazon S3 (Simple Storage Service) bucket, you do not have versioning enabled. Versioning allows you to preserve, retrieve, and restore every version of every object in your bucket. This means you can recover both previous versions of an object and deleted objects. Without versioning, if you accidentally delete or overwrite an object, there's no way of recovering it.

Here's how you can fix this issue. In your Terraform code, under your S3 bucket settings, you should add a block of code to enable versioning. 

Your original code may look something like this:

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "your_bucket_name"
  acl    = "private"

  tags = {
    Name        = "MyBucket"
    Environment = "Dev"
  }
}
```

To enable versioning, modify your code to look like this:

```hcl
resource "aws_s3_bucket" "bucket" {
  bucket = "your_bucket_name"
  acl    = "private"

  versioning {
    enabled = true
  }

  tags = {
    Name        = "MyBucket"
    Environment = "Dev"
  }
}
```

The "versioning" block with "enabled = true" is what turns on the versioning feature for the S3 bucket.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning)

---

## LOW Findings (1)

### 🔍 IAM Access Analyzer Not Enabled
**Severity:** LOW

**File:** `./test_data/iac_example/main.tf`  
**Line:** `1`  
**Description:** IAM Access Analyzer should be enabled and configured to continuously monitor resource permissions

**Explanation & Fix:**
This issue implies that IAM Access Analyzer, a feature in AWS that helps you verify your policies and avoid getting unauthorized access to your AWS resources, is not enabled in your Terraform file (main.tf), located in ./test_data/iac_example/. The file at line 1 lacks the required configuration that indicates this feature is enabled. This is a low severity issue, nevertheless, still poses possible security risks.

One way to fix this issue is by adding a resource block in your Terraform file for the IAM Access Analyzer, which will look like:

```hcl
resource "aws_accessanalyzer_analyzer" "example" {
  name     = "example"
  type     = "ACCOUNT"
  analyzer_name = "example-analyzer"
}
```

This is a simple example and the configuration may vary based on your requirements and setup. This will create an IAM Access Analyzer named "example" that will monitor access throughout your account. After adding this block to your main.tf file, you will need to run `terraform apply` to create the analyzer.

Note: Ensure that you have the AWS Identity and Access Management (IAM) permissions required to work with IAM Access Analyzer.

[📚 Learn more](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/accessanalyzer_analyzer)

---

