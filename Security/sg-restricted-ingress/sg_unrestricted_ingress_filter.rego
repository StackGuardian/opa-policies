package main

import future.keywords.if
import future.keywords.contains

# 1. Configuration
authorized_ports := {80, 443}

# 2. Resource Helpers
is_sg(type) if type == "aws_security_group"
is_sg_rule(type) if type == "aws_security_group_rule"
is_vpc_sg_ingress(type) if type == "aws_vpc_security_group_ingress_rule"

is_not_deleted(actions) if {
    count({a | a := actions[_]; a == "delete"}) == 0
}

# 3. Logic to determine if traffic is unrestricted (0.0.0.0/0 or ::/0)
is_unrestricted(after) if {
    # Handles legacy aws_security_group_rule
    cidrs := object.get(after, "cidr_blocks", [])
    cidrs[_] == "0.0.0.0/0"
}

is_unrestricted(after) if {
    # Handles modern aws_vpc_security_group_ingress_rule
    object.get(after, "cidr_ipv4", "") == "0.0.0.0/0"
}

is_unrestricted(after) if {
    # Handles IPv6 (Legacy and Modern)
    ipv6_cidrs := object.get(after, "ipv6_cidr_blocks", [])
    ipv6_cidrs[_] == "::/0"
}

is_unrestricted(after) if {
    object.get(after, "cidr_ipv6", "") == "::/0"
}

# 4. Port Validation Logic
is_unauthorized_port(from, to) if {
    from != to
}

is_unauthorized_port(from, to) if {
    from == to
    not authorized_ports[from]
}

# 5. DENY: Modern aws_vpc_security_group_ingress_rule
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_vpc_sg_ingress(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    
    is_unrestricted(after)
    
    from := object.get(after, "from_port", 0)
    to := object.get(after, "to_port", 0)
    is_unauthorized_port(from, to)
    
    msg := sprintf("❌ [SECURITY] %v: Unrestricted ingress (0.0.0.0/0) is only allowed on ports 80/443. Currently: %v-%v", [resource.address, from, to])
}

# 6. DENY: Legacy aws_security_group_rule
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_sg_rule(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    object.get(after, "type", "ingress") == "ingress"
    
    is_unrestricted(after)
    
    from := object.get(after, "from_port", 0)
    to := object.get(after, "to_port", 0)
    is_unauthorized_port(from, to)
    
    msg := sprintf("❌ [SECURITY] %v: Unrestricted legacy ingress rule detected on port(s) %v-%v.", [resource.address, from, to])
}

# 7. DENY: Inline ingress blocks
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_sg(resource.type)
    is_not_deleted(resource.change.actions)
    
    after := object.get(resource.change, "after", {})
    ingress_rules := object.get(after, "ingress", [])
    
    some j; rule := ingress_rules[j]
    is_unrestricted(rule)
    
    from := object.get(rule, "from_port", 0)
    to := object.get(rule, "to_port", 0)
    is_unauthorized_port(from, to)
    
    msg := sprintf("❌ [SECURITY] %v: Inline ingress rule %v allows unrestricted access on port(s) %v-%v.", [resource.address, j, from, to])
}

# 8. Status
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"