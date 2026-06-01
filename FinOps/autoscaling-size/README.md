# AWS Auto Scaling Group Size Compliance (OPA)

This policy prevents "oversized" infrastructure in non-production environments by restricting the minimum number of running instances.

## 💰 FinOps Rationale
Keeping multiple instances running in Dev or Test environments when they are idle is a major source of cloud waste. This policy enforces a "Scale-to-One" (or Zero) philosophy for all environments except Production.

### Compliance Rules
| Environment Tag | Allowed `min_size` | Status |
| :--- | :--- | :--- |
| **Production** | Any (defined by architecture) | ✅ Allowed |
| **Non-Production** | **0 or 1** | ✅ Allowed |
| **Non-Production** | **> 1** | ❌ **Blocked** |

---

## 🚀 Usage

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Pass/Fail
opa eval -i tfplan.json -d asg_min_size_limit.rego "data.main.status" --format pretty

# View Specific Violations
opa eval -i tfplan.json -d asg_min_size_limit.rego "data.main.deny" --format pretty

# View Full ASG Fleet Audit
opa eval -i tfplan.json -d asg_min_size_limit.rego "data.main.analysis" --format pretty
```