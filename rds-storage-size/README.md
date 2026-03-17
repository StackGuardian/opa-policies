# AWS RDS Storage Capacity Compliance (OPA)

This policy enforces a 500 GB storage limit for non-production RDS instances and clusters to prevent excessive "unutilized storage" costs.



## 💰 Storage Guardrails

RDS Storage is billed based on **provisioned capacity**, not actual data usage. To optimize costs, large disks (> 500 GB) are restricted to the **Production** environment.

| Environment | Max Allocated Storage | Status |
| :--- | :--- | :--- |
| **Production** | No Limit (defined by quota) | ✅ Allowed |
| **Non-Production** | **500 GB** | ❌ **Blocked if exceeded** |

---

## 🚀 Usage

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
# Check overall status
opa eval -i tfplan.json -d rds_storage_limit.rego "data.main.status" --format pretty
# View detailed storage violations
opa eval -i tfplan.json -d rds_storage_limit.rego "data.main.deny" --format pretty
# Run audit for all RDS storage
opa eval -i tfplan.json -d rds_storage_limit.rego "data.main.analysis" --format pretty