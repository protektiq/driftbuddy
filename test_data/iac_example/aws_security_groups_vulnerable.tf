# Purposefully vulnerable Security Groups configuration for testing
# This file contains multiple security flaws for demonstration

# CRITICAL: Security group allowing all traffic
resource "aws_security_group" "open_sg" {
  name        = "open-security-group"
  description = "CRITICAL: Allows all inbound and outbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "CRITICAL: Allow all inbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # CRITICAL: Open to entire internet
  }

  egress {
    description = "CRITICAL: Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # CRITICAL: Open to entire internet
  }

  tags = {
    Name = "Open Security Group"
  }
}

# HIGH: Security group with overly permissive SSH access
resource "aws_security_group" "ssh_open_sg" {
  name        = "ssh-open-security-group"
  description = "HIGH: SSH open to entire internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HIGH: SSH open to entire internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # HIGH: Should be restricted to specific IPs
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SSH Open Security Group"
  }
}

# HIGH: Security group with RDP open to internet
resource "aws_security_group" "rdp_open_sg" {
  name        = "rdp-open-security-group"
  description = "HIGH: RDP open to entire internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HIGH: RDP open to entire internet"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # HIGH: Should be restricted
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "RDP Open Security Group"
  }
}

# MEDIUM: Security group with database port open
resource "aws_security_group" "db_open_sg" {
  name        = "db-open-security-group"
  description = "MEDIUM: Database port open to internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "MEDIUM: MySQL port open to internet"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # MEDIUM: Should be restricted to VPC
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Database Open Security Group"
  }
}

# MEDIUM: Security group with web ports open
resource "aws_security_group" "web_open_sg" {
  name        = "web-open-security-group"
  description = "MEDIUM: Web ports open to internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "MEDIUM: HTTP open to internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MEDIUM: HTTPS open to internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Web Open Security Group"
  }
}

# LOW: Security group without description
resource "aws_security_group" "no_description_sg" {
  name   = "no-description-security-group"
  vpc_id = aws_vpc.main.id
  # LOW: Missing description

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# INFO: Security group without tags
resource "aws_security_group" "no_tags_sg" {
  name        = "no-tags-security-group"
  description = "Security group without tags"
  vpc_id      = aws_vpc.main.id
  # INFO: No tags for resource management

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VPC for security groups
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "Test VPC"
  }
}
