# AWS EC2 Graviton Enforcement Policy 

This policy mandates **AWS Graviton (ARM64)** CPUs for all compute resources. It blocks x86 instances to ensure a minimum of 20% cost savings and 40% better performance across the fleet.



## 🛡️ Covered Resources
This policy scans the following Terraform resources:
1. `aws_instance` (Standalone nodes)
2. `aws_launch_template` (ASG, EKS, and Spot blueprints)
3. `aws_spot_instance_request` (Ad-hoc spot requests)

## 📋 Compliance Criteria
* **Allowed:** Any instance type with a `g` suffix in the family name (e.g., `t4g.*`, `m6g.*`, `c7g.*`).
* **Blocked:** Standard x86 types (e.g., `t3.*`, `m5.*`) and non-Graviton GPU types (e.g., `g4dn.*`).

---

## 🚀 Usage

### 1. Generate Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# General Pass/Fail status
opa eval -i tfplan.json -d ec2_graviton.rego "data.main.status" --format pretty

# List all non-compliant resources
opa eval -i tfplan.json -d ec2_graviton.rego "data.main.deny" --format pretty