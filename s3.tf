data "aws_region" "current" {}

resource "aws_s3_bucket" "this" {
  bucket              = "${var.name}${var.append_region_suffix ? "-${data.aws_region.current.name}" : ""}"
  object_lock_enabled = var.object_lock_enabled
  force_destroy       = var.force_destroy
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

locals {
  // We have to do special things to allow CloudTrail digests to be written, since they
  // refuse to use KMS keys.
  // https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html
  allow_cloudtrail_digest = var.force_allow_cloudtrail_digest && var.kms_key_arn != null
  // This ARN represents the paths that CloudTrail Digest logs could be written to
  // https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html#cloudtrail-log-file-validation-digest-file-location
  cloudtrail_digest_arn = "${aws_s3_bucket.this.arn}/*/AWSLogs/*/CloudTrail-Digest/*"
}

// Create a bucket policy that requires all uploaded objects to be encrypted
data "aws_iam_policy_document" "this" {

  // Also apply all of the input policies, but don't let them override the security/encryption ones
  source_policy_documents = var.bucket_policy_json_documents

  // If an encryption header is provided, ensure it matches the default
  statement {
    sid    = "DenyIncorrectEncryptionHeader"
    effect = "Deny"

    // If we're not doing special CloudTrail rules, apply this policy to everything
    dynamic "principals" {
      for_each = !local.allow_cloudtrail_digest ? [1] : []
      content {
        type = "*"
        identifiers = [
          "*"
        ]
      }
    }

    // If we ARE doing special CloudTrail rules, apply this policy to everything EXCEPT CloudTrail
    dynamic "not_principals" {
      for_each = local.allow_cloudtrail_digest ? [1] : []
      content {
        type = "Service"
        identifiers = [
          "cloudtrail.amazonaws.com"
        ]
      }
    }

    // It's uploading objects that we want to prevent (if the request doesn't meet the conditions)
    actions = [
      "s3:PutObject",
    ]

    // Apply this statement to ALL resources in the bucket
    resources = [
      "${aws_s3_bucket.this.arn}/*",
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

  dynamic "statement" {
    for_each = local.allow_cloudtrail_digest ? [1] : []
    content {
      sid    = "DenyUnencryptedCloudTrail"
      effect = "Deny"

      // This applies to everything, INCLUDING CloudTrail
      principals {
        type = "*"
        identifiers = [
          "*"
        ]
      }

      // It's uploading objects that we want to prevent (if the request doesn't meet the conditions)
      actions = [
        "s3:PutObject",
      ]

      // Apply this statement to ALL resources in the bucket OTHER than those written by CloudTrail digests
      not_resources = [
        local.cloudtrail_digest_arn,
      ]

      // Trigger this deny if the header is provided AND
      condition {
        test     = "Null"
        variable = "s3:x-amz-server-side-encryption"
        values = [
          false
        ]
      }
      // It's not using the right type of encryption
      condition {
        test     = "StringNotEquals"
        variable = "s3:x-amz-server-side-encryption"
        values = [
          var.kms_key_arn == null ? "AES256" : "aws:kms",
        ]
      }
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

// Enable acceleration if desired. We do it this way (only create the resource
// if acceleration is enabled) because some regions don't support transfer
// acceleration, even if we try to set it to "Suspended".
resource "aws_s3_bucket_accelerate_configuration" "this" {
  count  = var.enable_transfer_acceleration ? 1 : 0
  bucket = aws_s3_bucket_policy.this.bucket
  status = "Enabled"
}
