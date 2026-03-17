# AWS EBS Storage Type Enforcement (Advanced Tagging)

This policy restricts high-cost **Provisioned IOPS (io1, io2)** volumes to Production environments.

## 🛠 Features
* **Launch Template Support:** Specifically designed to scan `tag_specifications` for Environment detection.
* **Hybrid Logic:** Corrected to handle instances, standalone volumes, and templates simultaneously.

## 🚀 Usage

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Overall Status
opa eval -i tfplan.json -d ec2_ebs_type_enforcement.rego "data.main.status" --format pretty

# View Specific Violations
opa eval -i tfplan.json -d ec2_ebs_type_enforcement.rego "data.main.deny" --format pretty