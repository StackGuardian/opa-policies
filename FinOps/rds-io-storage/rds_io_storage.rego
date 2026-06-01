package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_rds_instance(type) if type == "aws_db_instance"
is_rds_cluster(type) if type == "aws_rds_cluster"

# Helper for "OR" logic
is_any_rds(type) if is_rds_instance(type)
is_any_rds(type) if is_rds_cluster(type)

# 2. Environment check (safe version)
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

# 3. DENY rules
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_any_rds(resource.type)
    
    after := object.get(resource.change, "after", {})
    storage_type := object.get(after, "storage_type", "gp2")
    
    # Check if it's io1 or io2
    storage_type == "io1"
    not is_production(resource)
    msg := sprintf("❌ [FINOPS] %v: Storage 'io1' is Prohibited in non-prod.", [resource.address])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_any_rds(resource.type)
    
    after := object.get(resource.change, "after", {})
    storage_type := object.get(after, "storage_type", "gp2")
    
    storage_type == "io2"
    not is_production(resource)
    msg := sprintf("❌ [FINOPS] %v: Storage 'io2' is Prohibited in non-prod.", [resource.address])
}

# 4. Analysis (Audit log - Safe version)
analysis contains info if {
    some i; resource := input.resource_changes[i]
    is_any_rds(resource.type)
    
    is_prod := is_production(resource)
    after := object.get(resource.change, "after", {})
    storage := object.get(after, "storage_type", "gp2")
    
    # Lookup table zamiast if-else (kompatybilność wsteczna)
    labels := {true: "Production", false: "Other"}
    env_label := labels[is_prod]

    info := {
        "address": resource.address,
        "type": resource.type,
        "env": env_label,
        "storage": storage
    }
}

# 5. Final statuses
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"
