package main

import future.keywords.if
import future.keywords.contains

# 1. Resource Helpers
is_vpc(type) if type == "aws_vpc"
is_flow_log(type) if type == "aws_flow_log"

is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 2. Deep Scan: Verify that a VPC has an associated Flow Log in the config
# This handles "known after apply" for new VPC IDs
has_flow_log_configured(vpc_address) if {
    some i; resource_config := input.configuration.root_module.resources[i]
    is_flow_log(resource_config.type)
    
    expressions := object.get(resource_config, "expressions", {})
    vpc_id_expr := object.get(expressions, "vpc_id", {})
    references := object.get(vpc_id_expr, "references", [])
    
    some j; contains(references[j], vpc_address)
}

# 3. DENY: VPC exists without an associated Flow Log
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_vpc(resource.type)
    is_not_deleted(resource.change.actions)
    
    not has_flow_log_configured(resource.address)
    
    msg := sprintf("❌ [SECURITY] %v: VPC must have a Flow Log enabled for network visibility.", [resource.address])
}

# 4. DENY: Flow Log captures a narrow traffic type (Must be ALL)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_flow_log(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Requirement: traffic_type must be ALL
    # In Terraform, this usually defaults to ALL, but we enforce explicit 'ALL' for auditing.
    traffic_type := object.get(after, "traffic_type", "MISSING")
    traffic_type != "ALL"
    
    msg := sprintf("❌ [SECURITY] %v: Traffic type is set to '%v'. It must be 'ALL' to capture both ACCEPT and REJECT traffic.", [resource.address, traffic_type])
}

# 5. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"