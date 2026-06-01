package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_ec2_resource(type) if type == "aws_instance"
is_ec2_resource(type) if type == "aws_launch_template"
is_ec2_resource(type) if type == "aws_spot_instance_request"

# 2. Extract Instance Type
get_instance_type(resource) := t if {
    t := object.get(resource.change.after, "instance_type", "")
    t != ""
}

# 3. Graviton Detection Logic (Updated to regex.match)
is_graviton(instance_type) if {
    # This matches families like m6g, c7g, t4g, r6g
    # regex.match(pattern, string)
    regex.match(`^[a-z]+[0-9]+g(\..*)?$`, instance_type)
}

# 4. DENY rules
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ec2_resource(resource.type)
    
    instance_type := get_instance_type(resource)
    instance_type != ""
    not is_graviton(instance_type)
    
    msg := sprintf("❌ [FINOPS] %v (%v): Type '%v' is not Graviton. Use 'g' series (e.g., m6g, t4g) for 40%% better price-performance.", [resource.address, resource.type, instance_type])
}

# 5. Analysis & Status
analysis contains info if {
    some i; resource := input.resource_changes[i]
    is_ec2_resource(resource.type)
    
    instance_type := get_instance_type(resource)
    graviton_ready := is_graviton(instance_type)
    
    info := {
        "address": resource.address,
        "resource_type": resource.type,
        "instance_type": instance_type,
        "status": {true: "Compliant", false: "Non-Compliant"}[graviton_ready]
    }
}

allow if count(deny) == 0
status := "Pass" if allow else := "Fail"