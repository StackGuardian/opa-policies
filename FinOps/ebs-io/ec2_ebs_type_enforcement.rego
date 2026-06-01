package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_ebs_volume(type) if type == "aws_ebs_volume"
is_ec2_instance(type) if type == "aws_instance"
is_launch_template(type) if type == "aws_launch_template"

is_monitored_resource(type) if is_ebs_volume(type)
is_monitored_resource(type) if is_ec2_instance(type)
is_monitored_resource(type) if is_launch_template(type)

# 2. Expensive Types List
expensive_types := {"io1", "io2"}

# 3. Environment Helpers (The Fix)
# Check 1: Standard tags map (Instances/EBS)
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

# Check 2: ASG-style tag blocks
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    asg_tags := object.get(after, "tag", [])
    some i
    lower(asg_tags[i].key) == "environment"
    lower(asg_tags[i].value) == "production"
}

# Check 3: Launch Template tag_specifications (Fix for your specific issue)
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    specs := object.get(after, "tag_specifications", [])
    some s; spec := specs[s]
    # Look at any tag spec (instance or volume) that has the Production environment tag
    tags := object.get(spec, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

# 4. DENY rules
# Rule: Standalone EBS
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ebs_volume(resource.type)
    not is_production(resource)
    
    type := object.get(resource.change.after, "type", "gp2")
    expensive_types[type]
    msg := sprintf("❌ [FINOPS] %v: Expensive volume type '%v' is only allowed in Production.", [resource.address, type])
}

# Rule: EC2 Instances (Root & EBS)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ec2_instance(resource.type)
    not is_production(resource)
    
    # Check root_block_device
    root_devices := object.get(resource.change.after, "root_block_device", [])
    some j; root := root_devices[j]
    v_type := object.get(root, "volume_type", "gp2")
    expensive_types[v_type]
    msg := sprintf("❌ [FINOPS] %v: Provisioned IOPS root volume '%v' is forbidden in Non-Prod.", [resource.address, v_type])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ec2_instance(resource.type)
    not is_production(resource)
    
    # Check ebs_block_device
    ebs_devices := object.get(resource.change.after, "ebs_block_device", [])
    some k; ebs := ebs_devices[k]
    v_type := object.get(ebs, "volume_type", "gp2")
    expensive_types[v_type]
    msg := sprintf("❌ [FINOPS] %v: Provisioned IOPS EBS volume '%v' is forbidden in Non-Prod.", [resource.address, v_type])
}

# Rule: Launch Templates
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_launch_template(resource.type)
    not is_production(resource)
    
    mappings := object.get(resource.change.after, "block_device_mappings", [])
    some m; mapping := mappings[m]
    ebs_configs := object.get(mapping, "ebs", [])
    
    some e; ebs := ebs_configs[e]
    v_type := object.get(ebs, "volume_type", "gp2")
    expensive_types[v_type]
    msg := sprintf("❌ [FINOPS] %v: Launch Template uses forbidden '%v' volume type for Non-Prod.", [resource.address, v_type])
}

# 5. Status
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"