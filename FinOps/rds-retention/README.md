# AWS RDS Backup Retention Policy (OPA/Rego)

This repository contains an **Open Policy Agent (OPA)** policy written in Rego to enforce backup retention standards for AWS RDS instances (`aws_db_instance`) and Aurora Clusters (`aws_rds_cluster`).

## 📋 Overview
The policy ensures that database backups are configured according to the environment's criticality while preventing cost overruns.

### Policy Rules
| Environment Tag | Max Retention Period | Strict Mode |
| :--- | :--- | :--- |
| **Production** | **14 Days** | Required |
| **Non-Production** | **1 Day** | Required |

## ✨ Key Features
* **Strict Mode:** Blocks any plan where the retention period is not explicitly set in the HCL code.
* **Case-Insensitive:** Handles `Production` and `production` tags automatically.

## 🚀 Usage
1. Generate JSON plan: `terraform show -json tfplan > tfplan.json`
2. Evaluate: `opa eval -i tfplan.json -d rds_retention.rego "data.main.status" --format pretty`
