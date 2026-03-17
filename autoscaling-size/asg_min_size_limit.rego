package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definition
is_asg(type) if type == "aws_autoscaling_group"

# 2. Robust Environment check
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

is_production(resource) if {
    after := object.get(resource.change, "after", {})
    asg_tags := object.get(after, "tag", [])
    some i
    lower(asg_tags[i].key) == "environment"
    lower(asg_tags[i].value) == "production"
}

# 3. DENY rule
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_asg(resource.type)
    
    not is_production(resource)
    
    after := object.get(resource.change, "after", {})
    min_size := object.get(after, "min_size", 0)
    
    min_size > 1
    msg := sprintf("❌ [FINOPS] %v: min_size is %v. Non-production ASGs must have a min_size of 1 or 0.", [resource.address, min_size])
}

# 4. Final statuses
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"