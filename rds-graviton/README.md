# AWS RDS Graviton Enforcement Policy (OPA)

This policy mandates the use of **AWS Graviton** processors for all RDS instances and Aurora clusters. 

## 💰 FinOps Benefits
* **Cost:** Graviton instances are typically 20% cheaper than x86 equivalents.
* **Performance:** Up to 35% better performance for RDS workloads.
* **Effortless:** Managed service migration requires no application code changes.

## 📋 Compliance Rule
The `instance_class` must follow the Graviton naming convention (e.g., `db.m6g.*`, `db.t4g.*`, `db.r7g.*`).

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

Gemini said
Creating a Graviton-enforcement policy for RDS is arguably more impactful than for EC2. While EC2 requires you to refactor your application code for ARM64, RDS is a managed service—AWS handles the underlying OS and engine optimization for you. Switching an RDS instance to Graviton is often as simple as a single Terraform parameter change with zero code changes.

1. OPA Policy: rds_graviton_enforcement.rego
This policy targets aws_db_instance and aws_rds_cluster_instance (for Aurora). It uses the same "Triple-Check" environment logic we've established to ensure it correctly identifies Production vs. Non-Prod.

Code snippet
package main

import future.keywords.if
import future.keywords.contains

# 1. Resource definitions
is_rds_instance(type) if type == "aws_db_instance"
is_rds_cluster_instance(type) if type == "aws_rds_cluster_instance"

is_monitored_rds(type) if is_rds_instance(type)
is_monitored_rds(type) if is_rds_cluster_instance(type)

# 2. Graviton Detection Logic
# RDS Graviton instances always contain 'g' (e.g., db.m6g.large, db.t4g.micro, db.r7g.xlarge)
is_graviton(class) if {
    regex.match(`^db\.[a-z]+[0-9]+g\..*$`, class)
}

# 3. Environment Helpers (Triple-Check Logic)
is_production(resource) if {
    after := object.get(resource.change, "after", {})
    tags := object.get(after, "tags", {})
    lower(object.get(tags, "Environment", "")) == "production"
}

is_production(resource) if {
    # Handles ASG-style tag blocks if applicable to the resource type
    after := object.get(resource.change, "after", {})
    asg_tags := object.get(after, "tag", [])
    some i; lower(asg_tags[i].key) == "environment"
    lower(asg_tags[i].value) == "production"
}

# 4. DENY rules
deny contains msg if {
    some i; resource := input.resource_changes[i]
    is_monitored_rds(resource.type)
    
    # Extract the instance class (works for both standalone and cluster instances)
    class := object.get(resource.change.after, "instance_class", "")
    class != ""
    not is_graviton(class)
    
    msg := sprintf("❌ [FINOPS] %v: Instance class '%v' is not Graviton-based. Use a 'g' series instance (e.g., db.m6g, db.t4g) for better price-performance.", [resource.address, class])
}

# 5. Statuses
allow if count(deny) == 0
status := "Pass" if allow else := "Fail"
2. README.md (Copy/Paste Version)
Markdown
# AWS RDS Graviton Enforcement Policy (OPA)

This policy mandates the use of **AWS Graviton** processors for all RDS instances and Aurora clusters. 

## 💰 FinOps Benefits
* **Cost:** Graviton instances are typically 20% cheaper than x86 equivalents.
* **Performance:** Up to 35% better performance for RDS workloads.
* **Effortless:** Managed service migration requires no application code changes.

## 📋 Compliance Rule
The `instance_class` must follow the Graviton naming convention (e.g., `db.m6g.*`, `db.t4g.*`, `db.r7g.*`).

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Pass/Fail status
opa eval -i tfplan.json -d rds_graviton_enforcement.rego "data.main.status" --format pretty

# List non-compliant RDS resources
opa eval -i tfplan.json -d rds_graviton_enforcement.rego "data.main.deny" --format pretty