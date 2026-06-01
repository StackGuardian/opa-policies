package main

import future.keywords.if
import future.keywords.contains

# 1. Resource Helpers
is_s3_bucket(type) if type == "aws_s3_bucket"
is_s3_logging(type) if type == "aws_s3_bucket_logging"

# 2. Safety Helper: Check if resource is NOT being deleted
is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 3. Deep Scan: Verify that an S3 bucket has an associated logging configuration in code
# This avoids "known after apply" false positives for new bucket names
has_logging_configured(bucket_address) if {
    some i; resource_config := input.configuration.root_module.resources[i]
    is_s3_logging(resource_config.type)
    
    expressions := object.get(resource_config, "expressions", {})
    bucket_expr := object.get(expressions, "bucket", {})
    references := object.get(bucket_expr, "references", [])
    
    some j; contains(references[j], bucket_address)
}

# 4. DENY: Bucket exists without an associated aws_s3_bucket_logging resource
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_s3_bucket(resource.type)
    is_not_deleted(resource.change.actions)
    
    not has_logging_configured(resource.address)
    
    msg := sprintf("❌ [SECURITY] %v: S3 bucket is missing server access logging configuration. All buckets must have 'aws_s3_bucket_logging' explicitly defined.", [resource.address])
}

# 5. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"