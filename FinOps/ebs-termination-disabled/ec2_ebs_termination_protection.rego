package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_ec2_resource(type) if type == "aws_instance"
is_launch_template(type) if type == "aws_launch_template"

# Helper to check if value is "truthy" for deletion (handles string or bool)
is_deletion_enabled(val) if val == true
is_deletion_enabled(val) if val == "true"

# 2. DENY: Standalone EC2
deny contains msg if {
    some i; resource := input.resource_changes[i]
    resource.type == "aws_instance"
    
    after := object.get(resource.change, "after", {})
    
    # Check root_block_device
    root_devices := object.get(after, "root_block_device", [])
    some j; root := root_devices[j]
    is_deletion_enabled(object.get(root, "delete_on_termination", true))
    
    msg := sprintf("❌ [DATA-SAFETY] %v: Delete-on-Termination must be DISABLED (false) for root volumes.", [resource.address])
}

# 3. DENY: Launch Templates (The fix for your plan)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    resource.type == "aws_launch_template"
    
    after := object.get(resource.change, "after", {})
    mappings := object.get(after, "block_device_mappings", [])
    
    some m; mapping := mappings[m]
    ebs_configs := object.get(mapping, "ebs", [])
    
    # Iterate through ebs blocks (Launch templates store this as a list)
    some e; ebs := ebs_configs[e]
    is_deletion_enabled(object.get(ebs, "delete_on_termination", true))
    
    msg := sprintf("❌ [DATA-SAFETY] %v: Delete-on-Termination must be DISABLED (false) in Launch Template mappings.", [resource.address])
}

# 4. Statuses
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"