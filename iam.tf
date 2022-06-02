data "aws_iam_policy_document" "write" {
  // If we used a KMS key for the bucket, grant permissions on it
  dynamic "statement" {
    for_each = local.used_kms_key_arn != null ? [1] : []
    content {
      actions = [
        "kms:GenerateDataKey"
      ]
      resources = [
        local.used_kms_key_arn
      ]
    }
  }

  // Grant permission to put objects
  statement {
    actions = [
      "s3:PutObject"
    ]
    resources = [
      "${aws_s3_bucket.this.arn}/*",
    ]
  }
}

data "aws_iam_policy_document" "delete" {
  // Grant permission to delete objects
  statement {
    actions = [
      "s3:DeleteObject"
    ]
    resources = [
      "${aws_s3_bucket.this.arn}/*",
    ]
  }
}

data "aws_iam_policy_document" "read" {
  // If we used a KMS key for the bucket, grant permissions on it
  dynamic "statement" {
    for_each = local.used_kms_key_arn != null ? [1] : []
    content {
      actions = [
        "kms:Decrypt"
      ]
      resources = [
        local.used_kms_key_arn
      ]
    }
  }

  // Grant permission to get objects
  statement {
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectAttributes",
      "s3:GetObjectVersionAttributes",
      "s3:GetObjectTagging",
      "s3:GetObjectVersionTagging",
    ]
    resources = [
      "${aws_s3_bucket.this.arn}/*",
    ]
  }
  // Grant permission to list objects
  statement {
    actions = [
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.this.arn,
    ]
  }
}
