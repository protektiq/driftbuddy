resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "iam:passrole"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:sqs:us-east-2:account-ID-without-hyphens:queue1"
      }
    ]
  }
  EOF
}
