# AWS RDS Non-Prod Scheduling Enforcement (OPA)

This policy enforces mandatory scheduling tags for all non-production RDS Instances and Aurora Clusters. This enables automated start/stop functionality to reduce database costs during idle hours.

## 💰 FinOps Guardrail
RDS costs are significant. By using the `Schedule-NP-01` tag, you ensure that dev/test databases are only active when needed.

| Tag Key | Example Value | Case Sensitive? |
| :--- | :--- | :--- |
| **Schedule-NP-01** | `SCH-CET-19h-7h` | **No** (Automatic normalization) |

### Allowed Schedule Values
The policy supports standard CET schedules (e.g., `sch-cet-19h-7h`, `sch-cet-fri19h-mon7h`, etc.).

---

## 🚀 Usage

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Pass/Fail status
opa eval -i tfplan.json -d rds_schedule_tag_enforcement.rego "data.main.status" --format pretty

# View Specific Violations
opa eval -i tfplan.json -d rds_schedule_tag_enforcement.rego "data.main.deny" --format pretty