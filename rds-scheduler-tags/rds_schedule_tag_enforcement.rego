package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_rds_instance(type) if type == "aws_db_instance"
is_rds_cluster(type) if type == "aws_rds_cluster"

is_monitored_resource(type) if is_rds_instance(type)
is_monitored_resource(type) if is_rds_cluster(type)

# 2. Allowed Schedule Values (Normalized to lowercase)
allowed_schedules_lc := {
    "sch-cet-19h-7h",
    "sch-cet-20h-8h",
    "sch-cet-15:30h-3:30h",
    "sch-cet-19h-3:30h",
    "sch-cet-fri19h-mon7h",
    "sch-cet-fri15:30h-mon3:30h",
    "sch-cet-fri19h-mon3:30h",
    "sch-cet-08h-20h",
    "sch-cet-17h-9h",
    "sch-cet-20:00h-3:30h",
    "sch-cet-19h",
    "sch-cet-19:30h-6:30h",
    "sch-cet-19h-5h"
}

# 3. Helpers
is_non_production(resource) if {
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) != "production"
}

# 4. DENY rules
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_monitored_resource(resource.type)
    is_non_production(resource)
    
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    
    # Extract tag value and convert to lowercase for comparison
    val_raw := object.get(tags, "Schedule-NP-01", "MISSING")
    val_lc := lower(val_raw)
    
    # Check against the lowercase set
    not allowed_schedules_lc[val_lc]
    
    msg := sprintf("❌ [FINOPS] %v: Non-production RDS must have a valid 'Schedule-NP-01' tag. Found: '%v'.", [resource.address, val_raw])
}

# 5. Analysis & Status
analysis contains info if {
    some i; resource := input.resource_changes[i]
    is_monitored_resource(resource.type)
    
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    schedule := object.get(tags, "Schedule-NP-01", "None")
    
    info := {
        "address": resource.address,
        "type": resource.type,
        "provided_schedule": schedule,
        "is_non_prod": is_non_production(resource)
    }
}

allow if count(deny) == 0
status := "Pass" if allow else := "Fail"