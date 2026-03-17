# AWS RDS Instance Size Compliance (OPA)

This policy enforces instance size limits for `aws_db_instance`, `aws_rds_cluster`, and `aws_rds_cluster_instance` to control AWS costs.



## 💰 Size Limits
The policy uses a ranking system to ensure environments stay within budget.

| Environment | Max Allowed Size | Ranking |
| :--- | :--- | :--- |
| **Production** | **12xlarge** | Rank 9 |
| **Non-Prod** | **2xlarge** | Rank 6 |

## 🚀 Usage

### 1. Generate Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
