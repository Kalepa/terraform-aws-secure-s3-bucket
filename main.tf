data "aws_region" "current" {
  count = var.region == null ? 1 : 0
}

data "aws_caller_identity" "current" {
  count = var.account_id == null ? 1 : 0
}

locals {
  bucket_arn_placeholder = "{BUCKET_ARN}"
  # Use provided values or fall back to data sources
  region     = var.region != null ? var.region : data.aws_region.current[0].name
  account_id = var.account_id != null ? var.account_id : data.aws_caller_identity.current[0].account_id
}
