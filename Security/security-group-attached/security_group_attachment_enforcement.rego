package main

import future.keywords.if
import future.keywords.contains

# 1. Resource Helpers
is_security_group(type) if type == "aws_security_group"

is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 2. Deep Scan: Check if the Security Group is referenced anywhere in the configuration
# This scans all resource expressions for any reference to the SG address.
has_attachment_reference(sg_address) if {
    some i; resource_config := input.configuration.root_module.resources[i]
    
    # We ignore the SG resource itself to avoid self-references
    resource_config.address != sg_address
    
    expressions := object.get(resource_config, "expressions", {})
    
    # Walk through all expressions to see if any reference the SG
    some expr_key; expr := expressions[expr_key]
    references := object.get(expr, "references", [])
    
    some j; contains(references[j], sg_address)
}

# 3. DENY: Security Group exists but is not referenced by any other resource
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_security_group(resource.type)
    is_not_deleted(resource.change.actions)
    
    # Fail if no other resource in the plan references this SG
    not has_attachment_reference(resource.address)
    
    msg := sprintf("❌ [HYGIENE] %v: Security group is not attached to any resource. Unused security groups should be removed to simplify audits.", [resource.address])
}

# 4. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"