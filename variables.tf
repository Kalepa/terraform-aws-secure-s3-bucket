variable "name" {
  description = "The name to use for the bucket."
  type        = string
}

variable "versioned" {
  description = "Whether the bucket should be versioned."
  type        = bool
}

variable "mfa_delete_enabled" {
  description = "Whether MFA Delete should be enabled."
  type        = bool
  default     = false
}

variable "bucket_policy_json_documents" {
  description = "A list of JSON-encoded policy documents to apply to the bucket."
  type        = list(string)
  default     = []
}

variable "kms_key_arn" {
  description = "The ARN of the KMS key to use for this bucket. If not provided, AES256 encryption will be enforced instead."
  type        = string
  default     = null
}

variable "enable_transfer_acceleration" {
  description = "Whether to enable transfer acceleration for this bucket."
  type        = bool
  default     = false
}

variable "block_public_acls" {
  description = "The `block_public_acls` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
}

variable "block_public_policy" {
  description = "The `block_public_policy` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
}

variable "ignore_public_acls" {
  description = "The `ignore_public_acls` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
}

variable "restrict_public_buckets" {
  description = "The `restrict_public_buckets` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
}

variable "object_ownership" {
  description = "The `rule.object_ownership` value of an `aws_s3_bucket_ownership_controls` resource that is applied to this bucket."
  type        = string
  default     = "BucketOwnerEnforced"
}

variable "append_region_suffix" {
  description = "If `true`, a suffix in the form of `-{region_name}` will be appended to the bucket name. This is convenient if you're creating buckets in multiple regions and don't want to manually specify the region name in each one for uniqueness."
  type        = bool
  default     = false
}

variable "object_lock_enabled" {
  description = "Indicates whether this bucket has an Object Lock configuration enabled."
  type        = bool
  default     = false
}

variable "force_destroy" {
  description = "A boolean that indicates all objects (including any locked objects) should be deleted from the bucket so that the bucket can be destroyed without error."
  type        = bool
  default     = false
}

variable "force_allow_cloudtrail_digest" {
  description = "Whether to allow AES256 (AWS-managed key) encryption for paths checked by CloudTrail digest writers. Even when a bucket and a CloudTrail are both set to use KMS encryption, digests are still written using AWS-managed key AES256 encryption (). This variable only has an effect when the `kms_key_id` variable is provided and not `null`."
  type        = bool
  default     = false
}
