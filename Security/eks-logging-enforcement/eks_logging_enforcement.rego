package main

import future.keywords.if
import future.keywords.contains

# 1. Helper to identify EKS Cluster resources
is_eks_cluster(type) if type == "aws_eks_cluster"

# 2. Safety Helper: Check if resource is NOT being deleted
is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 3. Define the master list of all 5 required log types
required_log_types := {"api", "audit", "authenticator", "controllerManager", "scheduler"}

# 4. DENY: EKS Cluster with missing or incomplete log types enabled
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_eks_cluster(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Extract the configured log types into a set
    enabled_log_list := object.get(after, "enabled_cluster_log_types", [])
    enabled_log_set := {log | log := enabled_log_list[_]}
    
    # Version-resilient set difference: find required logs NOT present in enabled_log_set
    missing_logs := {log | required_log_types[log]; not enabled_log_set[log]}
    
    # Trigger violation if any log types are missing
    count(missing_logs) > 0
    
    msg := sprintf("❌ [SECURITY] %v: EKS cluster is missing mandatory control-plane log types: %v. All 5 types must be explicitly enabled.", [resource.address, missing_logs])
}

# 5. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"