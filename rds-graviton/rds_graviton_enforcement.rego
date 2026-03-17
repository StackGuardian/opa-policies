package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_rds_instance(type) if type == "aws_db_instance"
is_rds_cluster_instance(type) if type == "aws_rds_cluster_instance"

is_monitored_rds(type) if is_rds_instance(type)
is_monitored_rds(type) if is_rds_cluster_instance(type)

# 2. Graviton Detection Logic
# RDS Graviton instances always contain 'g' (e.g., db.m6g.large, db.t4g.micro, db.r7g.xlarge)
is_graviton(class) if {
    regex.match(`^db\.[a-z]+[0-9]+g\..*$`, class)
}

# 3. Environment Helpers (Triple-Check Logic)
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

is_production(resource) if {
    # Handles ASG-style tag blocks if applicable to the resource type
    after := object.get(resource.change, "after", {})
    asg_tags := object.get(after, "tag", [])
    some i; lower(asg_tags[i].key) == "environment"
    lower(asg_tags[i].value) == "production"
}

# 4. DENY rules
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_monitored_rds(resource.type)
    
    # Extract the instance class (works for both standalone and cluster instances)
    class := object.get(resource.change.after, "instance_class", "")
    class != ""
    not is_graviton(class)
    
    msg := sprintf("❌ [FINOPS] %v: Instance class '%v' is not Graviton-based. Use a 'g' series instance (e.g., db.m6g, db.t4g) for better price-performance.", [resource.address, class])
}

# 5. Statuses
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"