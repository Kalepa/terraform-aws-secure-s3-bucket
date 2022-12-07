variable "name" {
  description = "The name to use for the bucket."
  type        = string
  validation {
    condition     = var.name != null
    error_message = "`name` may not be `null`."
  }
}

variable "versioned" {
  description = "Whether the bucket should be versioned."
  type        = bool
  validation {
    condition     = var.versioned != null
    error_message = "`versioned` may not be `null`."
  }
}

variable "mfa_delete_enabled" {
  description = "Whether MFA Delete should be enabled."
  type        = bool
  default     = false
}
locals {
  mfa_delete_enabled = var.mfa_delete_enabled != null ? var.mfa_delete_enabled : false
}

variable "bucket_policy_json_documents" {
  description = "A list of JSON-encoded policy documents to apply to the bucket. The placeholder \"{BUCKET_ARN}\" can be used to reference the ARN of the bucket the policy is being applied to."
  type        = list(string)
  default     = []
}
locals {
  bucket_policy_json_documents = var.bucket_policy_json_documents != null ? var.bucket_policy_json_documents : []
}

variable "kms_key_arn" {
  description = "The ARN of the KMS key to use for this bucket. If not provided, AES256 encryption will be enforced instead."
  type        = string
  default     = null
}

variable "create_new_kms_key" {
  description = "Whether to create a new KMS key for use with this bucket. If `kms_key_arn` is not provided (null), a new key will be created. If `kms_key_arn` is provided, a replica of that key will be created."
  type        = bool
  default     = false
}
locals {
  create_new_kms_key = var.create_new_kms_key != null ? var.create_new_kms_key : false
}

variable "create_replica_kms_key" {
  description = "Whether to create a replica key, using `kms_key_arn` as the source key."
  type        = bool
  default     = false
}
locals {
  create_replica_kms_key = var.create_replica_kms_key != null ? var.create_replica_kms_key : false
}

variable "kms_key_policy_json_documents" {
  description = "A list of JSON-encoded policy documents to apply to the KMS key, if one should be created."
  type        = list(string)
  default     = []
}
locals {
  kms_key_policy_json_documents = var.kms_key_policy_json_documents != null ? var.kms_key_policy_json_documents : []
}

variable "enable_transfer_acceleration" {
  description = "Whether to enable transfer acceleration for this bucket."
  type        = bool
  default     = false
}
locals {
  enable_transfer_acceleration = var.enable_transfer_acceleration != null ? var.enable_transfer_acceleration : false
}

variable "block_public_acls" {
  description = "The `block_public_acls` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
}
locals {
  block_public_acls = var.block_public_acls != null ? var.block_public_acls : true
}

variable "block_public_policy" {
  description = "The `block_public_policy` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
}
locals {
  block_public_policy = var.block_public_policy != null ? var.block_public_policy : true
}

variable "ignore_public_acls" {
  description = "The `ignore_public_acls` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
}
locals {
  ignore_public_acls = var.ignore_public_acls != null ? var.ignore_public_acls : true
}

variable "restrict_public_buckets" {
  description = "The `restrict_public_buckets` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
}
locals {
  restrict_public_buckets = var.restrict_public_buckets != null ? var.restrict_public_buckets : true
}

variable "object_ownership" {
  description = "The `rule.object_ownership` value of an `aws_s3_bucket_ownership_controls` resource that is applied to this bucket."
  type        = string
  default     = "BucketOwnerEnforced"
}
locals {
  object_ownership = var.object_ownership != null ? var.object_ownership : "BucketOwnerEnforced"
}

variable "append_region_suffix" {
  description = "If `true`, a suffix in the form of `-{region_name}` will be appended to the bucket name. This is convenient if you're creating buckets in multiple regions and don't want to manually specify the region name in each one for uniqueness."
  type        = bool
  default     = false
}
locals {
  append_region_suffix = var.append_region_suffix != null ? var.append_region_suffix : false
}

variable "object_lock_enabled" {
  description = "Indicates whether this bucket has an Object Lock configuration enabled."
  type        = bool
  default     = false
}
locals {
  object_lock_enabled = var.object_lock_enabled != null ? var.object_lock_enabled : false
}

variable "force_destroy" {
  description = "A boolean that indicates all objects (including any locked objects) should be deleted from the bucket so that the bucket can be destroyed without error."
  type        = bool
  default     = false
}
locals {
  force_destroy = var.force_destroy != null ? var.force_destroy : false
}

variable "force_allow_cloudtrail_digest" {
  description = "Whether to allow AES256 (AWS-managed key) encryption for paths checked by CloudTrail digest writers. Even when a bucket and a CloudTrail are both set to use KMS encryption, digests are still written using AWS-managed key AES256 encryption (). This variable only has an effect when the `kms_key_id` variable is provided and not `null`."
  type        = bool
  default     = false
}
locals {
  force_allow_cloudtrail_digest = var.force_allow_cloudtrail_digest != null ? var.force_allow_cloudtrail_digest : false
}

variable "tags" {
  description = "Tags to apply to S3 bucket created in this module."
  type        = map(string)
  default     = {}
}
