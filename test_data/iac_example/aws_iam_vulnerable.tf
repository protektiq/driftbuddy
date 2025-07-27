# Purposefully vulnerable IAM configuration for testing
# This file contains multiple security flaws for demonstration

# CRITICAL: Overly permissive IAM policy
resource "aws_iam_policy" "admin_policy" {
  name = "admin-policy"
  description = "CRITICAL: Overly permissive admin policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"  # CRITICAL: Allows all actions
        Resource = "*"  # CRITICAL: Allows all resources
      }
    ]
  })
}

# HIGH: IAM user with admin access
resource "aws_iam_user" "admin_user" {
  name = "admin-user"

  tags = {
    Name = "Admin User"
  }
}

resource "aws_iam_user_policy_attachment" "admin_attachment" {
  user       = aws_iam_user.admin_user.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

# HIGH: IAM role with excessive permissions
resource "aws_iam_role" "excessive_role" {
  name = "excessive-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "excessive_role_policy" {
  name = "excessive-role-policy"
  role = aws_iam_role.excessive_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "ec2:*",
          "rds:*",
          "lambda:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# MEDIUM: IAM user with access keys
resource "aws_iam_user" "access_key_user" {
  name = "access-key-user"

  tags = {
    Name = "Access Key User"
  }
}

resource "aws_iam_access_key" "user_key" {
  user = aws_iam_user.access_key_user.name
  # MEDIUM: No rotation policy specified
}

# MEDIUM: IAM policy without conditions
resource "aws_iam_policy" "unconditional_policy" {
  name = "unconditional-policy"
  description = "MEDIUM: Policy without conditions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::my-bucket/*"
        # MEDIUM: Missing conditions for IP restrictions, MFA, etc.
      }
    ]
  })
}

# LOW: IAM user without MFA
resource "aws_iam_user" "no_mfa_user" {
  name = "no-mfa-user"

  tags = {
    Name = "No MFA User"
  }
  # LOW: No MFA configuration
}

# LOW: IAM role without session duration limits
resource "aws_iam_role" "no_session_limit_role" {
  name = "no-session-limit-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  # LOW: No max_session_duration specified
}

# INFO: IAM user without tags
resource "aws_iam_user" "untagged_user" {
  name = "untagged-user"
  # INFO: No tags for resource management
}
