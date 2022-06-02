data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  bucket_arn_placeholder = "{BUCKET_ARN}"
}
