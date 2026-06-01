package main

import future.keywords.if
import future.keywords.contains

# 1. Helper to identify the EBS encryption by default resource
is_ebs_default_encryption(type) if type == "aws_ebs_encryption_by_default"

# 2. Safety Helper: Check if resource is NOT being deleted
is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 3. DENY: EBS Default Encryption is disabled or missing
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ebs_default_encryption(resource.type)
    
    # Only evaluate if the resource is being created or updated
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Robust boolean check: enabled must be explicitly true
    # 'not ... == true' catches cases where it is false, null, or omitted.
    not object.get(after, "enabled", false) == true
    
    msg := sprintf("❌ [SECURITY] %v: EBS encryption by default must be enabled for the account in this region.", [resource.address])
}

# 4. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"