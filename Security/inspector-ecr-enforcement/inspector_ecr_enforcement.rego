package main

import future.keywords.if
import future.keywords.contains

# 1. Helper to identify Inspector V2 Enabler resources
is_inspector_enabler(type) if type == "aws_inspector2_enabler"

# 2. Safety Helper: Check if resource is NOT being deleted
is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 3. DENY: Inspector resource_types array is empty or missing ECR
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_inspector_enabler(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Extract the enabled resource types list
    resource_types_list := object.get(after, "resource_types", [])
    
    # Convert list to a set for comprehensive member evaluation
    resource_types_set := {type | type := resource_types_list[_]}
    
    # Trigger violation if ECR is not explicitly part of the enabled scan dimensions
    not resource_types_set["ECR"]
    
    msg := sprintf("❌ [SECURITY] %v: Amazon Inspector V2 is configured, but 'ECR' scanning is disabled. ECR must be included in resource_types.", [resource.address])
}

# 4. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"