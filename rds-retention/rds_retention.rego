package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions for RDS instances and clusters
is_rds_resource(type) if {
    type == "aws_db_instance"
}
is_rds_resource(type) if {
    type == "aws_rds_cluster"
}

# 2. Environment and Unknown checks
is_production(resource) if {
    tags := object.get(resource.change.after, "tags", {})
    # Convert tag value to lowercase before comparison to handle "Production", "production", etc.
    lower(object.get(tags, "Environment", "")) == "production"
}

# Helper to check if a value is "(known after apply)"
is_unknown(resource, field) if {
    object.get(resource.change.after_unknown, field, false) == true
}

# 3. DENY rules (Violations)

# NEW: Option B - Strict check for (known after apply)
deny contains msg if {
    some i
    resource := input.resource_changes[i]
    is_rds_resource(resource.type)
    is_unknown(resource, "backup_retention_period")

    msg := sprintf("❌ [STRICT] %v: backup_retention_period is (known after apply). You must explicitly set this value in your Terraform code.", [resource.address])
}

# Production resources: max 14 days
deny contains msg if {
    some i
    resource := input.resource_changes[i]
    is_rds_resource(resource.type)
    is_production(resource)
    retention := object.get(resource.change.after, "backup_retention_period", 0)
    retention > 14
    msg := sprintf("❌ [PROD] %v: retention %v exceeds 14 days", [resource.address, retention])
}

# Non-production resources: max 1 day
deny contains msg if {
    some i
    resource := input.resource_changes[i]
    is_rds_resource(resource.type)
    not is_production(resource)
    retention := object.get(resource.change.after, "backup_retention_period", 0)
    retention > 1
    msg := sprintf("❌ [NON-PROD] %v: retention %v exceeds 1 day", [resource.address, retention])
}

# 4. Analysis (Logs - useful for debugging and audit trails)
analysis contains info if {
    some i
    resource := input.resource_changes[i]
    is_rds_resource(resource.type)
    env := is_production(resource)
    retention := object.get(resource.change.after, "backup_retention_period", 0)
    
    info := {
        "address": resource.address,
        "env": {true: "Production", false: "Other"}[env],
        "retention": retention
    }
}

# 5. Final statuses (Ensures 'allow' and 'status' are always defined to avoid 'undefined' results)
allow if {
    count(deny) == 0
}

status := "Pass" if {
    allow
} else := "Fail"