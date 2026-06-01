# AWS RDS Cost Control Policy (OPA/Rego)

This repository contains an **Open Policy Agent (OPA)** policy designed to optimize AWS costs by enforcing strict rules for RDS High Availability (Multi-AZ) and Aurora Clusters.



## 💰 FinOps Overview

The goal of this policy is to prevent expensive database configurations in non-production environments. Multi-AZ deployments and Aurora clusters can significantly increase your AWS bill, so we restrict them to the **Production** environment only.

### Policy Rules

| Resource Type | Environment Tag (`Environment`) | Allowed Configuration |
| :--- | :--- | :--- |
| **aws_db_instance** | `Production` | Single-AZ or Multi-AZ |
| **aws_db_instance** | `Other` (Dev, Staging, etc.) | **Single-AZ only** (`multi_az = false`) |
| **aws_rds_cluster** | `Production` | Allowed |
| **aws_rds_cluster** | `Other` | **PROHIBITED** (Use standard RDS instead) |

---

## ✨ Policy Logic

### 1. Multi-AZ Restriction
In standard RDS, enabling Multi-AZ effectively doubles the ince cost because AWS maintains a synchronous standby in another Availability Zone. This policy ensures this cost is only incurred where high availability is mission-critical.

### 2. Aurora Cluster Block
Aurora Clusters have a higher base cost and different storage pricing. For development or testing, standard RDS instances (like `db.t3.micro`) are much more cost-effective.

### 3. Case-Insensitive Tags
The policy is robust against tagging variations. It will correctly identify `Production`, `production`, or `PRODUCTION` as valid production environments.

---

## 🚀 How to Use

### 1. Prepare Terraform Plan
Export your plan to JSON:
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
