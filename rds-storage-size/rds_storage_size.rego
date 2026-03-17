package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_db_instance(type) if type == "aws_db_instance"
is_rds_cluster(type) if type == "aws_rds_cluster"

# Helper for "OR" logic
is_monitored_resource(type) if is_db_instance(type)
is_monitored_resource(type) if is_rds_cluster(type)

# 2. Environment check (case-insensitive)
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

# 3. DENY rules
# Rule: Non-Production storage limit (Max 500 GB)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_monitored_resource(resource.type)
    
    # Only check if it is NOT production
    not is_production(resource)
    
    after := object.get(resource.change, "after", {})
    # Default to 0 if not specified (e.g., Aurora Serverless or specific engines)
    storage := object.get(after, "allocated_storage", 0)
    
    storage > 500
    msg := sprintf("❌ [FINOPS] %v: Storage size %v GB exceeds the 500 GB limit for non-production environments.", [resource.address, storage])
}

# 4. Analysis (Audit log)
analysis contains info if {
    some i; resource := input.resource_changes[i]
    is_monitored_resource(resource.type)
    
    after := object.get(resource.change, "after", {})
    storage := object.get(after, "allocated_storage", 20) # 20 is a common AWS default
    is_prod := is_production(resource)
    
    labels := {true: "Production", false: "Other"}
    env_label := labels[is_prod]

    info := {
        "address": resource.address,
        "type": resource.type,
        "allocated_storage": storage,
        "env": env_label
    }
}

# 5. Final statuses
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"

# 6. DEBUG Rules
debug_storage contains s if {
    some i; resource := input.resource_changes[i]
    is_monitored_resource(resource.type)
    s := object.get(resource.change.after, "allocated_storage", "not_defined")
}