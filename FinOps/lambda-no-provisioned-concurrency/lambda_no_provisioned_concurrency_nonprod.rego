package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_lambda_pc(type) if type == "aws_lambda_provisioned_concurrency_config"
is_lambda_alias(type) if type == "aws_lambda_alias"

# 2. Environment Helper: The Cross-Resource Bridge
is_production_context(resource) if {
    # Step A: Get the function name from the PC Config or Alias
    func_name := object.get(resource.change.after, "function_name", "")
    
    # Step B: Find the Lambda Function in the same plan with that name
    some i; other_res := input.resource_changes[i]
    other_res.type == "aws_lambda_function"
    object.get(other_res.change.after, "function_name", "") == func_name
    
    # Step C: Check the Function's tags for 'production'
    f_tags := object.get(other_res.change.after, "tags", {})
    lower(object.get(f_tags, "Environment", "")) == "production"
}

# 3. DENY rules
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_lambda_pc(resource.type)
    
    # If the parent function is NOT production, deny the PC Config
    not is_production_context(resource)
    
    msg := sprintf("❌ [FINOPS] %v: Provisioned Concurrency is forbidden because parent function '%v' is not tagged as Production.", [resource.address, object.get(resource.change.after, "function_name", "unknown")])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_lambda_alias(resource.type)
    
    # Check if this alias has an inline PC configuration
    after := object.get(resource.change, "after", {})
    pc_configs := object.get(after, "provisioned_concurrency_config", [])
    count(pc_configs) > 0
    
    # If it does, check the context
    not is_production_context(resource)
    
    msg := sprintf("❌ [FINOPS] %v: Inline Provisioned Concurrency in Alias is forbidden for Non-Production functions.", [resource.address])
}

# 4. Status and Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"