output "bucket_id" {
  description = "The ID of the bucket that was created."
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "The ARN of the bucket that was created."
  value       = aws_s3_bucket.this.arn
}

output "bucket_regional_domain_name" {
  description = "The regional domain name of the bucket that was created."
  value       = aws_s3_bucket.this.bucket_regional_domain_name
}

output "complete" {
  depends_on = [
    aws_s3_bucket_accelerate_configuration.this
  ]
  description = "Always `true`, but doesn't return until everything in this module has been applied."
  value       = true
}

output "region_name" {
  description = "The name of the region that this bucket is being created in."
  value       = data.aws_region.current.name
}

output "outbound_replication_policy_json" {
  description = "A JSON policy that grants permission to replicate objects out of this bucket."
  value       = data.aws_iam_policy_document.outbound_replication.json
}

output "inbound_replication_policy_json" {
  description = "A JSON policy that grants permission to replicate objects into this bucket."
  value       = data.aws_iam_policy_document.inbound_replication.json
}

output "kms_key_arn" {
  description = "The ARN of the KMS key that is used for this bucket. If a KMS key is not used, it will be `null`."
  value       = var.kms_key_arn
}
