package main

import future.keywords.if
import future.keywords.contains

# 1. Helper to identify EKS Cluster resources
is_eks_cluster(type) if type == "aws_eks_cluster"

# 2. Safety Helper: Check if resource is NOT being deleted
is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 3. DENY: EKS Cluster with public endpoint access enabled
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_eks_cluster(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    vpc_configs := object.get(after, "vpc_config", [])
    
    # Safely unpack the inner objects of the vpc_config array
    some j; config := vpc_configs[j]
    
    # Triggers DENY if explicitly true or if default/omitted (which behaves as true in AWS)
    object.get(config, "endpoint_public_access", true) == true
    
    msg := sprintf("❌ [SECURITY] %v: EFS cluster API server endpoint must not be publicly accessible. Set 'endpoint_public_access = false' inside the vpc_config block.", [resource.address])
}

# 4. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"