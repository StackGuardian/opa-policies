package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_ebs_volume(type) if type == "aws_ebs_volume"
is_ec2_instance(type) if type == "aws_instance"
is_launch_template(type) if type == "aws_launch_template"

is_monitored_storage(type) if is_ebs_volume(type)
is_monitored_storage(type) if is_ec2_instance(type)
is_monitored_storage(type) if is_launch_template(type)

# 2. Environment Helpers (Triple-Check Logic)
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

is_production(resource) if {
    after := object.get(resource.change, "after", {})
    asg_tags := object.get(after, "tag", [])
    some i; lower(asg_tags[i].key) == "environment"
    lower(asg_tags[i].value) == "production"
}

is_production(resource) if {
    after := object.get(resource.change, "after", {})
    specs := object.get(after, "tag_specifications", [])
    some s; spec := specs[s]
    tags := object.get(spec, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

# 3. DENY rules: Non-Prod max 500GB
# Rule: Standalone EBS
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ebs_volume(resource.type)
    not is_production(resource)
    
    size := object.get(resource.change.after, "size", 8) # AWS default is 8GB
    size > 500
    msg := sprintf("❌ [FINOPS] %v: EBS size %vGB exceeds the 500GB limit for Non-Prod.", [resource.address, size])
}

# Rule: EC2 Instances
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ec2_instance(resource.type)
    not is_production(resource)
    
    # Check root_block_device
    root_devices := object.get(resource.change.after, "root_block_device", [])
    some j; root := root_devices[j]
    v_size := object.get(root, "volume_size", 8)
    v_size > 500
    msg := sprintf("❌ [FINOPS] %v: Root volume size %vGB exceeds 500GB limit.", [resource.address, v_size])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_ec2_instance(resource.type)
    not is_production(resource)
    
    # Check ebs_block_device
    ebs_devices := object.get(resource.change.after, "ebs_block_device", [])
    some k; ebs := ebs_devices[k]
    v_size := object.get(ebs, "volume_size", 8)
    v_size > 500
    msg := sprintf("❌ [FINOPS] %v: Additional EBS volume %vGB exceeds 500GB limit.", [resource.address, v_size])
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
    v_size := object.get(ebs, "volume_size", 8)
    v_size > 500
    msg := sprintf("❌ [FINOPS] %v: Launch Template volume %vGB exceeds 500GB limit.", [resource.address, v_size])
}

# 4. Status
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"