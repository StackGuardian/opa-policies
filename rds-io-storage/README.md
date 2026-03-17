# AWS RDS Storage Compliance Policy (OPA)

This repository contains an **Open Policy Agent (OPA)** policy to enforce cost-optimized storage choices for AWS RDS Instances and Aurora Clusters.



## 💰 FinOps Overview
Provisioned IOPS (**io1**, **io2**) are significantly more expensive than General Purpose (**gp3**). This policy acts as a financial guardrail by restricting high-cost storage to **Production** environments only.

### Policy Rules
| Resource Type | Storage Type | Environment Tag | Result |
| :--- | :--- | :--- | :--- |
| `aws_db_instance` | `io1` / `io2` | `Production` | ✅ **Allowed** |
| `aws_rds_cluster` | `io1` / `io2` | `Production` | ✅ **Allowed** |
| Any RDS | `io1` / `io2` | `Non-Prod` | ❌ **Blocked** |
| Any RDS | `gp2` / `gp3` | Any | ✅ **Allowed** |

---

## 🚀 Usage

### 1. Generate Terraform Plan
OPA evaluates the JSON output of your Terraform plan.
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
opa eval -i tfplan.json -d rds_io_storage.rego "data.main.status" --format pretty 