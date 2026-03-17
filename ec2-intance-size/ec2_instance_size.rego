package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_ec2_resource(type) if type == "aws_instance"
is_ec2_resource(type) if type == "aws_launch_template"
is_ec2_resource(type) if type == "aws_spot_instance_request"

is_monitored_size_resource(type) if is_ec2_resource(type)

# 2. Size Ranking Map (Consistent with RDS ranking)
size_rank := {
    "nano": 1, "micro": 2, "small": 3, "medium": 4, "large": 5, 
    "xlarge": 6, "2xlarge": 7, "4xlarge": 8, "8xlarge": 9, 
    "12xlarge": 10, "16xlarge": 11, "24xlarge": 12, "32xlarge": 13, "48xlarge": 14
}

# 3. Helpers
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    
    # Check Standard Tags
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

is_production(resource) if {
    after := object.get(resource.change, "after", {})
    
    # Check ASG-style Tags (List of blocks)
    asg_tags := object.get(after, "tag", [])
    some i
    lower(asg_tags[i].key) == "environment"
    lower(asg_tags[i].value) == "production"
}

get_instance_size(class) := size if {
    # Splits "m6g.2xlarge" into ["m6g", "2xlarge"]
    parts := split(class, ".")
    size := parts[count(parts) - 1]
}

get_class(resource) := class if {
    class := object.get(resource.change.after, "instance_type", "")
    class != ""
}

# 4. DENY rules
# Rule: Non-Prod max 2xlarge (Rank 7)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_monitored_size_resource(resource.type)
    not is_production(resource)
    
    class := get_class(resource)
    size := get_instance_size(class)
    
    size_rank[size] > 7
    msg := sprintf("❌ [COST] %v: Size '%v' exceeds the '2xlarge' limit for non-production.", [resource.address, size])
}

# Rule: Production max 12xlarge (Rank 10)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_monitored_size_resource(resource.type)
    is_production(resource)
    
    class := get_class(resource)
    size := get_instance_size(class)
    
    size_rank[size] > 10
    msg := sprintf("❌ [COST] %v: Size '%v' exceeds the '12xlarge' limit even for Production.", [resource.address, size])
}

# 5. Analysis & Status
analysis contains info if {
    some i; resource := input.resource_changes[i]
    is_monitored_size_resource(resource.type)
    
    class := get_class(resource)
    is_prod := is_production(resource)
    
    info := {
        "address": resource.address,
        "type": resource.type,
        "class": class,
        "env": {true: "Production", false: "Non-Prod"}[is_prod]
    }
}

allow if count(deny) == 0
status := "Pass" if allow else := "Fail"