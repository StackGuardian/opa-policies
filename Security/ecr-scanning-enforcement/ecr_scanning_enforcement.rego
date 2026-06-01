package main

import future.keywords.if
import future.keywords.contains

# 1. Resource Helpers
is_ecr_repository(type) if type == "aws_ecr_repository"

is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 2. DENY: ECR repository is missing scanning configurations or configured incorrectly
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ecr_repository(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Extract the image_scanning_configuration list from the resource plan
    scanning_configs := object.get(after, "image_scanning_configuration", [])
    
    # Fail if the scanning configuration block is completely omitted
    count(scanning_configs) == 0
    
    msg := sprintf("❌ [SECURITY] %v: ECR Repository is missing an 'image_scanning_configuration' block. Scan on push or continuous scan must be enabled.", [resource.address])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ecr_repository(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    scanning_configs := object.get(after, "image_scanning_configuration", [])
    
    some j; config := scanning_configs[j]
    
    # Robust boolean check: scan_on_push must be true
    not object.get(config, "scan_on_push", false) == true
    
    # Note: If your environment relies on account-level enhanced continuous scanning (Inspector),
    # the repository-level 'scan_on_push' parameter can still be coupled with it.
    
    msg := sprintf("❌ [SECURITY] %v: ECR Repository must have automated vulnerability scanning active. Set 'scan_on_push = true'.", [resource.address])
}

# 3. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"