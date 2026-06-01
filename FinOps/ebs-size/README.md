# AWS EBS Storage Capacity Enforcement (OPA)

This policy enforces a **500 GB storage limit** for all non-production EBS volumes to prevent excessive "zombie" storage costs and accidental over-provisioning.



## 💰 FinOps Guardrail
While individual 1TB volumes might seem small, they add up across a large dev fleet. This policy forces teams to justify large storage requirements by restricting them to Production environments only.

| Environment | Max Volume Size | Default Action |
| :--- | :--- | :--- |
| **Production** | Unlimited | ✅ Allowed |
| **Non-Prod** | **500 GB** | ❌ **Blocked if > 500** |

## 🚀 Usage

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Overall Status
opa eval -i tfplan.json -d ec2_ebs_storage_limit.rego "data.main.status" --format pretty

# View Specific Violations
opa eval -i tfplan.json -d ec2_ebs_storage_limit.rego "data.main.deny" --format pretty