package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definition
is_s3_encryption_config(type) if type == "aws_s3_bucket_server_side_encryption_configuration"

# 2. DENY rule: Strict enforcement
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_s3_encryption_config(resource.type)
    
    after := object.get(resource.change, "after", {})
    rules := object.get(after, "rule", [])
    some j; rule := rules[j]
    
    # Check if algorithm is KMS
    encryption := object.get(rule, "apply_server_side_encryption_by_default", [{}])[0]
    sse_algo := object.get(encryption, "sse_algorithm", "")
    sse_algo == "aws:kms"
    
    # STRICT CHECK:
    # If it is null or false, we block it.
    # In a new resource plan, 'null' means the user didn't provide a value 
    # that Terraform could resolve to 'true'.
    val := object.get(rule, "bucket_key_enabled", false)
    not val == true
    
    msg := sprintf("❌ [FINOPS] %v: SSE-KMS requires 'bucket_key_enabled = true'. Currently set to: %v. Please add this to your Terraform code to save up to 99%% on KMS costs.", [resource.address, val])
}

# 3. Final statuses
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"

# 4. Debugging rule (Run this to see exactly what OPA sees)
debug_s3 contains res if {
    some i; resource := input.resource_changes[i]
    is_s3_encryption_config(resource.type)
    rules := object.get(resource.change.after, "rule", [])
    res := {
        "address": resource.address,
        "bucket_key_val": object.get(rules[0], "bucket_key_enabled", "MISSING")
    }
}