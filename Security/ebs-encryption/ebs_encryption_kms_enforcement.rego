package main

import future.keywords.if
import future.keywords.contains

# 1. Configuration: Define the expected KMS Key resource name or ARN
# Based on your standards, we look for the Bpost EBS key reference.
expected_kms_reference := "aws_kms_key.Bpost_ebs"

# 2. Resource Helpers
is_ebs_volume(type) if type == "aws_ebs_volume"

is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 3. Deep Scan: Check configuration for the specific KMS Key reference
# This handles "known after apply" scenarios for new keys.
has_correct_kms_reference(address) if {
    some i; resource_config := input.configuration.root_module.resources[i]
    resource_config.address == address
    
    expressions := object.get(resource_config, "expressions", {})
    kms_expr := object.get(expressions, "kms_key_id", {})
    references := object.get(kms_expr, "references", [])
    
    # Verify the code references the specific authorized KMS resource
    some j; contains(references[j], expected_kms_reference)
}

# 4. DENY: EBS volume is not encrypted
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ebs_volume(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Check if encryption is disabled (false, null, or missing)
    not object.get(after, "encrypted", false) == true
    
    msg := sprintf("❌ [SECURITY] %v: EBS volume must have encryption enabled.", [resource.address])
}

# 5. DENY: EBS volume is encrypted with the wrong key
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ebs_volume(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Only check the key if encryption is enabled
    object.get(after, "encrypted", false) == true
    
    # Verify the reference in the configuration
    not has_correct_kms_reference(resource.address)
    
    msg := sprintf("❌ [SECURITY] %v: EBS volume must be encrypted using '%v'.", [resource.address, expected_kms_reference])
}

# 6. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"