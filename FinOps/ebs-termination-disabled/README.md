# AWS EC2 EBS Termination Protection Policy 

This policy prevents data loss by ensuring EBS volumes are not automatically deleted when an instance is terminated. It focuses on standalone instances and **Launch Templates**.

## 🛡️ Governance Logic
By securing the `aws_launch_template`, we automatically cover:
* **Auto Scaling Groups (ASG)**
* **EKS Managed Node Groups**
* **EC2 Spot Fleet Requests**

## 📋 Compliance Rules
The attribute `delete_on_termination` must be explicitly set to `false`.

---

## 🚀 Usage

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Pass/Fail
opa eval -i tfplan.json -d ec2_ebs_termination_protection.rego "data.main.status" --format pretty

# List violations
opa eval -i tfplan.json -d ec2_ebs_termination_protection.rego "data.main.deny" --format pretty