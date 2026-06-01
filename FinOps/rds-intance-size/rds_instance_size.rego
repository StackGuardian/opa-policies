package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_db_instance(type) if type == "aws_db_instance"
is_cluster_instance(type) if type == "aws_rds_cluster_instance"
is_rds_cluster(type) if type == "aws_rds_cluster"

# Helper for "OR" logic (Identifying any resource that has a size/class)
is_monitored_size_resource(type) if is_db_instance(type)
is_monitored_size_resource(type) if is_cluster_instance(type)
is_monitored_size_resource(type) if is_rds_cluster(type)

# 2. Size Ranking Map
size_rank := {
    "micro": 1, "small": 2, "medium": 3, "large": 4, 
    "xlarge": 5, "2xlarge": 6, "4xlarge": 7, "8xlarge": 8, 
    "12xlarge": 9, "16xlarge": 10, "24xlarge": 11, "32xlarge": 12
}

# 3. Helpers
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

get_instance_size(class) := size if {
    parts := split(class, ".")
    size := parts[count(parts) - 1]
}

# Logic to extract class from different attribute names
get_class(resource) := class if {
    class := object.get(resource.change.after, "instance_class", "")
    class != ""
}

get_class(resource) := class if {
    class := object.get(resource.change.after, "db_cluster_instance_class", "")
    class != ""
}

# 4. DENY rules
# Non-Prod check (Max 2xlarge)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_monitored_size_resource(resource.type)
    
    not is_production(resource)
    
    class := get_class(resource)
    size := get_instance_size(class)
    
    size_rank[size] > 6
    msg := sprintf("❌ [COST] %v: Size '%v' exceeds the '2xlarge' limit for non-production.", [resource.address, size])
}

# Production check (Max 12xlarge)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_monitored_size_resource(resource.type)
    
    is_production(resource)
    
    class := get_class(resource)
    size := get_instance_size(class)
    
    size_rank[size] > 9
    msg := sprintf("❌ [COST] %v: Size '%v' exceeds the '12xlarge' limit even for Production.", [resource.address, size])
}

# 5. Analysis
analysis contains info if {
    some i; resource := input.resource_changes[i]
    is_monitored_size_resource(resource.type)
    
    class := get_class(resource)
    is_prod := is_production(resource)
    
    info := {
        "address": resource.address,
        "resource_type": resource.type,
        "class": class,
        "env": {true: "Production", false: "Other"}[is_prod]
    }
}

allow if count(deny) == 0
status := "Pass" if allow else := "Fail"