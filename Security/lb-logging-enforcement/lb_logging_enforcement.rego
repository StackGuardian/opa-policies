package main

import future.keywords.if
import future.keywords.contains

# 1. Configuration Parameter: Define the authorized central storage bucket name
expected_bucket_name := "bpost-central-security-logs-bucket"

# 2. Resource Helpers
is_modern_lb(type) if type == "aws_lb"
is_modern_lb(type) if type == "aws_alb"
is_classic_lb(type) if type == "aws_elb"

is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 3. DENY: Modern Load Balancers (ALB/NLB) missing or misconfigured logging
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_modern_lb(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # In Terraform, access_logs is an array containing a single configuration object
    access_logs_list := object.get(after, "access_logs", [])
    
    # Catch cases where the access_logs block is omitted completely
    count(access_logs_list) == 0
    
    msg := sprintf("❌ [SECURITY] %v: ALB/NLB is missing an 'access_logs' block. Logging must be explicitly enabled.", [resource.address])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_modern_lb(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    access_logs_list := object.get(after, "access_logs", [])
    
    some j; config := access_logs_list[j]
    
    # Rule Validation: Reject if logging is disabled (false, null, missing)
    not object.get(config, "enabled", false) == true
    
    msg := sprintf("❌ [SECURITY] %v: ALB/NLB access logging is disabled. Set 'enabled = true'.", [resource.address])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_modern_lb(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    access_logs_list := object.get(after, "access_logs", [])
    
    some j; config := access_logs_list[j]
    object.get(config, "enabled", false) == true
    
    # Rule Validation: Check destination bucket parameter matches
    bucket := object.get(config, "bucket", "MISSING")
    bucket != expected_bucket_name
    
    msg := sprintf("❌ [SECURITY] %v: ALB/NLB log bucket '%v' is unauthorized. Must deliver logs to '%v'.", [resource.address, bucket, expected_bucket_name])
}

# 4. DENY: Classic Load Balancers (CLB/ELB) missing or misconfigured logging
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_classic_lb(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    access_logs_list := object.get(after, "access_logs", [])
    
    count(access_logs_list) == 0
    
    msg := sprintf("❌ [SECURITY] %v: Classic LB is missing an 'access_logs' block.", [resource.address])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_classic_lb(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    access_logs_list := object.get(after, "access_logs", [])
    
    some j; config := access_logs_list[j]
    not object.get(config, "enabled", false) == true
    
    msg := sprintf("❌ [SECURITY] %v: Classic LB access logging is disabled.", [resource.address])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_classic_lb(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    access_logs_list := object.get(after, "access_logs", [])
    
    some j; config := access_logs_list[j]
    object.get(config, "enabled", false) == true
    
    bucket := object.get(config, "bucket", "MISSING")
    bucket != expected_bucket_name
    
    msg := sprintf("❌ [SECURITY] %v: Classic LB log bucket '%v' must match expected parameter '%v'.", [resource.address, bucket, expected_bucket_name])
}

# 5. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"