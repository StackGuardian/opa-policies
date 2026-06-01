package main

import future.keywords.if
import future.keywords.contains

# 1. Resource Helpers
is_detector(type) if type == "aws_guardduty_detector"
is_org_config(type) if type == "aws_guardduty_organization_configuration"
is_detector_feature(type) if type == "aws_guardduty_detector_feature"

# 2. Safety Helper: Check if resource is NOT being deleted
is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 3. DENY: Basic Enablement & Frequency (Tier 1 Baseline)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_detector(resource.type)
    
    # Safely check that the detector is not being deleted
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Requirement: Must be enabled
    not object.get(after, "enable", false) == true
    msg := sprintf("❌ [SECURITY] %v: Amazon GuardDuty detector must be enabled.", [resource.address])
}

deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_detector(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Requirement: 15-minute frequency for Bpost compliance
    freq := object.get(after, "finding_publishing_frequency", "SIX_HOURS")
    freq != "FIFTEEN_MINUTES"
    msg := sprintf("❌ [SECURITY] %v: Publishing frequency must be 'FIFTEEN_MINUTES'.", [resource.address])
}

# 4. DENY: Missing Org-Wide Auto-Enablement (T2 Baseline)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_org_config(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    # Requirement: Ensure ALL members are auto-enabled
    auto_enable := object.get(after, "auto_enable_organization_members", "NONE")
    auto_enable != "ALL"
    
    msg := sprintf("❌ [GOVERNANCE] %v: auto_enable_organization_members must be set to 'ALL'.", [resource.address])
}

# 5. DENY: Missing Mandatory Data Sources (T2 Baseline)
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_org_config(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    datasources := object.get(after, "datasources", [{}])[0]
    
    # Requirement: S3 Protection must be auto-enabled for T2
    s3 := object.get(object.get(datasources, "s3_logs", {}), "auto_enable", "NONE")
    s3 != "ALL"
    
    msg := sprintf("❌ [GOVERNANCE] %v: S3 Logs must be auto-enabled for ALL member accounts.", [resource.address])
}

# 6. DENY: Missing Runtime Monitoring for Tier 3
deny contains msg if {
    some i; res := input.resource_changes[i]
    is_detector(res.type)
    is_not_deleted(res.change.actions)
    
    # Check if the resource is tagged as Tier 3
    tags := object.get(res.change.after, "tags", {})
    lower(object.get(tags, "Tier", "")) == "t3"
    
    # Requirement: Tier 3 requires Runtime Monitoring
    not plan_has_runtime_monitoring
    
    msg := "❌ [COMPLIANCE] Tier 3 accounts must have 'aws_guardduty_detector_feature' for RUNTIME_MONITORING enabled."
}

plan_has_runtime_monitoring if {
    some i; res := input.resource_changes[i]
    is_detector_feature(res.type)
    is_not_deleted(res.change.actions)
    
    after := object.get(res.change, "after", {})
    object.get(after, "name", "") == "RUNTIME_MONITORING"
    object.get(after, "status", "") == "ENABLED"
}

# 7. Status Evaluation
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"