# AWS EC2 Instance Size Compliance Policy (OPA)

This policy enforces upper limits on EC2 instance sizes based on the environment to prevent budget overruns. It covers standalone instances, launch templates, and spot requests.



## 💰 FinOps Sizing Limits

| Environment | Max Allowed Size | Ranking | Example Blocked |
| :--- | :--- | :--- | :--- |
| **Production** | **12xlarge** | Rank 10 | `m6g.16xlarge` |
| **Non-Prod** | **2xlarge** | Rank 7 | `c7g.4xlarge` |

## 🚀 Usage

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Pass/Fail status
opa eval -i tfplan.json -d ec2_instance_size.rego "data.main.status" --format pretty

# View specific violations
opa eval -i tfplan.json -d ec2_instance_size.rego "data.main.deny" --format pretty
