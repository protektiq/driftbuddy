resource "aws_s3_bucket" "example" {
  bucket = "driftbuddy-test-bucket"
  acl    = "public-read"

  tags = {
    Name        = "driftbuddy-test"
    Environment = "dev"
  }
}
