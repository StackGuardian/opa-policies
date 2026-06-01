package main

import future.keywords.if
import future.keywords.contains

# 1. Resource Helpers
is_efs(type) if type == "aws_efs_file_system"

is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 2. Deep Scan: Check configuration for the specific Bpost KMS Key reference
# This ensures compliance even if the ARN is 'known after apply'
has_bpost_kms_reference(address) if {
    some i; resource_config := input.configuration.root_module.resources[i]
    resource_config.address == address
    
    expressions := object.get(resource_config, "expressions", {})
    kms_expr := object.get(expressions, "kms_key_id", {})
    references := object.get(kms_expr, "references", [])
    
    # Check if the code references the specific Bpost KMS resource
    some j; contains(references[j], "aws_kms_key.Bpost_efs")
}

# 3. DENY: EFS is not encrypted
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_efs(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Fail if encrypted is false, null, or missing
    not object.get(after, "encrypted", false) == true
    
    msg := sprintf("❌ [SECURITY] %v: EFS file system must have encryption at rest enabled.", [resource.address])
}

# 4. DENY: EFS is encrypted but using an unauthorized key
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_efs(resource.type)
    is_not_deleted(resource.change.actions)
    
    # Only check key if encryption is enabled
    after := object.get(resource.change, "after", {})
    object.get(after, "encrypted", false) == true
    
    # Check if the HCL configuration references the Bpost KMS key
    not has_bpost_kms_reference(resource.address)
    
    msg := sprintf("❌ [SECURITY] %v: EFS must be encrypted with 'aws_kms_key.Bpost_efs.arn'. Use of default or other keys is prohibited.", [resource.address])
}

# 5. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"