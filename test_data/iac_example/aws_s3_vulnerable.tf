# Purposefully vulnerable S3 configuration for testing
# This file contains multiple security flaws for demonstration

# CRITICAL: Public read-write access
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-test-bucket-12345"
  acl    = "public-read-write"  # CRITICAL: Allows public read/write

  tags = {
    Name = "Public Test Bucket"
  }
}

# MEDIUM: No versioning enabled
resource "aws_s3_bucket" "unversioned_bucket" {
  bucket = "my-unversioned-bucket-12345"
  acl    = "private"

  # MEDIUM: Missing versioning configuration
  # versioning {
  #   enabled = true
  # }

  tags = {
    Name = "Unversioned Bucket"
  }
}

# MEDIUM: No logging enabled
resource "aws_s3_bucket" "unlogged_bucket" {
  bucket = "my-unlogged-bucket-12345"
  acl    = "private"

  # MEDIUM: Missing logging configuration
  # logging {
  #   target_bucket = aws_s3_bucket.log_bucket.id
  #   target_prefix = "logs/"
  # }

  tags = {
    Name = "Unlogged Bucket"
  }
}

# HIGH: No encryption at rest
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-bucket-12345"
  acl    = "private"

  # HIGH: Missing server-side encryption
  # server_side_encryption_configuration {
  #   rule {
  #     apply_server_side_encryption_by_default {
  #       sse_algorithm = "AES256"
  #     }
  #   }
  # }

  tags = {
    Name = "Unencrypted Bucket"
  }
}

# HIGH: No bucket policy to restrict access
resource "aws_s3_bucket" "no_policy_bucket" {
  bucket = "my-no-policy-bucket-12345"
  acl    = "private"

  # HIGH: Missing bucket policy for access control
  # policy = jsonencode({
  #   Version = "2012-10-17"
  #   Statement = [
  #     {
  #       Effect = "Deny"
  #       Principal = "*"
  #       Action = "s3:*"
  #       Resource = "${aws_s3_bucket.no_policy_bucket.arn}/*"
  #       Condition = {
  #         StringNotEquals = {
  #           "aws:PrincipalArn" = "arn:aws:iam::123456789012:user/authorized-user"
  #         }
  #       }
  #     }
  #   ]
  # })

  tags = {
    Name = "No Policy Bucket"
  }
}

# LOW: No lifecycle policy
resource "aws_s3_bucket" "no_lifecycle_bucket" {
  bucket = "my-no-lifecycle-bucket-12345"
  acl    = "private"

  # LOW: Missing lifecycle configuration
  # lifecycle_rule {
  #   id      = "log"
  #   enabled = true
  #   prefix  = "log/"
  #   expiration {
  #     days = 90
  #   }
  # }

  tags = {
    Name = "No Lifecycle Bucket"
  }
} 