package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_rds_instance(type) if type == "aws_db_instance"
is_rds_cluster(type) if type == "aws_rds_cluster"

# Helper for "OR" logic: identifies any RDS resource we want to monitor
is_monitored_resource(type) if is_rds_instance(type)
is_monitored_resource(type) if is_rds_cluster(type)

# 2. Environment check (case-insensitive)
is_production(resource) if {
    tags := object.get(resource.change.after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

# 3. DENY rules (Violations)

# Rule A: Block Multi-AZ for non-production RDS instances
deny contains msg if {
    some i
    resource := input.resource_changes[i]
    is_rds_instance(resource.type)
    
    # Check if Multi-AZ is enabled
    multi_az_enabled := object.get(resource.change.after, "multi_az", false)
    multi_az_enabled == true

    # Violation if it's NOT a production environment
    not is_production(resource)

    msg := sprintf("❌ [COST] %v: Multi-AZ is enabled on non-production. Use Single-AZ to save costs.", [resource.address])
}

# Rule B: Block Aurora Clusters for non-production environments
deny contains msg if {
    some i
    resource := input.resource_changes[i]
    is_rds_cluster(resource.type)

    # Violation if it's NOT a production environment
    not is_production(resource)

    msg := sprintf("❌ [FINOPS] %v: Aurora Clusters are prohibited outside of Production. Use a standard RDS instance instead.", [resource.address])
}

# 4. Analysis (Audit log)
analysis contains info if {
    some i
    resource := input.resource_changes[i]
    
    # Using the helper rule instead of (A or B) syntax
    is_monitored_resource(resource.type)
    
    is_prod := is_production(resource)
    
    info := {
        "address": resource.address,
        "type": resource.type,
        "env": {true: "Production", false: "Other"}[is_prod],
        "status": "Checked"
    }
}

# 5. Final statuses
allow if {
    count(deny) == 0
}

status := "Pass" if {
    allow
} else := "Fail"