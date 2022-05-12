data "aws_region" "current" {}

resource "aws_s3_bucket" "this" {
  bucket = "${var.bucket_name}${var.append_region_suffix ? data.aws_region.current.name : ""}"
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status     = var.versioned ? "Enabled" : "Suspended"
    mfa_delete = var.mfa_delete_enabled ? "Enabled" : "Disabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket_versioning.this.bucket
  rule {
    bucket_key_enabled = var.kms_key_arn == null ? null : true
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn == null ? null : var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket_server_side_encryption_configuration.this.bucket
  block_public_acls       = var.block_public_acls
  block_public_policy     = var.block_public_policy
  ignore_public_acls      = var.ignore_public_acls
  restrict_public_buckets = var.restrict_public_buckets
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket_public_access_block.this.bucket
  rule {
    object_ownership = var.object_ownership
  }
}

// Create a bucket policy that requires all uploaded objects to be encrypted
data "aws_iam_policy_document" "this" {

  // Also apply all of the input policies, but don't let them override the security/encryption ones
  source_policy_documents = var.bucket_policy_json_documents

  // If an encryption header is provided, ensure it matches the default
  statement {
    sid    = "DenyIncorrectEncryptionHeader"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "s3:PutObject",
    ]
    // This is a temporary patch to allow CloudTrail to pass the write access test
    // TODO: switch this back to "resources" with a wildcard to apply to all resources
    not_resources = [
      "${aws_s3_bucket.this.arn}/AWSLogs/*/*",
    ]
    // Trigger this deny if the header is provided AND
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values = [
        false
      ]
    }
    // Its value doesn't match the expected one
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values = [
        var.kms_key_arn == null ? "AES256" : "aws:kms",
      ]
    }
  }

  // If we're using KMS, then ensure that if a KMS key is provided, it matches the default
  dynamic "statement" {
    for_each = var.kms_key_arn == null ? [] : [var.kms_key_arn]
    content {
      sid    = "DenyIncorrectKmsKeyId"
      effect = "Deny"
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      actions = [
        "s3:PutObject",
      ]
      resources = [
        "${aws_s3_bucket.this.arn}/*",
      ]
      // Trigger this deny if the header is provided AND
      condition {
        test     = "Null"
        variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
        values = [
          false
        ]
      }
      // Its value doesn't match the expected one
      condition {
        test     = "StringNotEquals"
        variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
        values = [
          statement.value
        ]
      }
    }
  }
}

// Set the policy on the bucket
resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket_ownership_controls.this.bucket
  policy = data.aws_iam_policy_document.this.json
}

// Enable acceleration if desired
resource "aws_s3_bucket_accelerate_configuration" "this" {
  bucket = aws_s3_bucket_policy.this.bucket
  status = var.enable_transfer_acceleration ? "Enabled" : "Suspended"
}
