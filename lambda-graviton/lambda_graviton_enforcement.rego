package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definition
is_lambda_layer(type) if type == "aws_lambda_layer_version"

# 2. Architecture Check
# Checks if 'arm64' is present in the compatible_architectures list
is_arm_compatible(architectures) if {
    some i
    architectures[i] == "arm64"
}

# 3. DENY rule
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_lambda_layer(resource.type)
    
    after := object.get(resource.change, "after", {})
    
    # compatible_architectures is optional in TF; if missing, it's a risk for Graviton envs
    archs := object.get(after, "compatible_architectures", [])
    
    not is_arm_compatible(archs)
    
    msg := sprintf("❌ [RUNTIME-SAFETY] %v: Lambda Layer must explicitly support 'arm64' to be compatible with Graviton functions. Found: %v", [resource.address, archs])
}

# 4. Status
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"