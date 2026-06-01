package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions (The "OR" logic done correctly)
is_monitored_ebs_resource(type) if type == "aws_instance"
is_monitored_ebs_resource(type) if type == "aws_launch_template"
is_monitored_ebs_resource(type) if type == "aws_ebs_volume"

# 2. DENY: Standalone EBS Volumes
deny contains msg if {
    some i; resource := input.resource_changes[i]
    resource.type == "aws_ebs_volume"
    
    after := object.get(resource.change, "after", {})
    type := object.get(after, "type", "gp2")
    
    type != "gp3"
    msg := sprintf("❌ [FINOPS] %v: Standalone volume type is '%v'. Use 'gp3'.", [resource.address, type])
}

# 3. DENY: EC2 Root Block Devices
deny contains msg if {
    some i; resource := input.resource_changes[i]
    resource.type == "aws_instance"
    
    root_devices := object.get(resource.change.after, "root_block_device", [])
    some j; root := root_devices[j]
    v_type := object.get(root, "volume_type", "gp2")
    
    v_type != "gp3"
    msg := sprintf("❌ [FINOPS] %v: Root volume is '%v'. Use 'gp3'.", [resource.address, v_type])
}

# 4. DENY: EC2 Additional EBS Block Devices
deny contains msg if {
    some i; resource := input.resource_changes[i]
    resource.type == "aws_instance"
    
    ebs_devices := object.get(resource.change.after, "ebs_block_device", [])
    some k; ebs := ebs_devices[k]
    v_type := object.get(ebs, "volume_type", "gp2")
    
    v_type != "gp3"
    msg := sprintf("❌ [FINOPS] %v: EBS block device is '%v'. Use 'gp3'.", [resource.address, v_type])
}

# 5. DENY: Launch Templates (Used by ASG/EKS)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    resource.type == "aws_launch_template"
    
    mappings := object.get(resource.change.after, "block_device_mappings", [])
    some m; mapping := mappings[m]
    ebs_configs := object.get(mapping, "ebs", [])
    
    some e; ebs := ebs_configs[e]
    v_type := object.get(ebs, "volume_type", "gp2")
    
    v_type != "gp3"
    msg := sprintf("❌ [FINOPS] %v: Launch Template volume is '%v'. Use 'gp3'.", [resource.address, v_type])
}

# 6. Analysis (Safe version)
analysis contains info if {
    some i; resource := input.resource_changes[i]
    is_monitored_ebs_resource(resource.type)
    
    info := {
        "address": resource.address,
        "resource_type": resource.type,
        "status": "Checked"
    }
}

# 7. Final statuses
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"