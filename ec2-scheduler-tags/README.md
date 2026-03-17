# AWS EC2 Non-Prod Scheduling Enforcement (OPA)

This policy enforces mandatory scheduling tags for all non-production EC2 instances and Launch Templates. This ensures that resources can be automatically stopped during off-hours to reduce cloud spend.

## 💰 FinOps Guardrail
Non-production environments (Dev, Test, Staging) are typically only needed during specific hours. This policy requires the `Schedule-NP-01` tag with a predefined value.

### Allowed Schedule Values
* `SCH-CET-19h-7h`
* `SCH-CET-20h-8h`
* `SCH-CET-15:30h-3:30h`
* ... (refer to policy for full list)

---

## 🚀 Usage

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Pass/Fail status
opa eval -i tfplan.json -d ec2_schedule_tag_enforcement.rego "data.main.status" --format pretty

# View Specific Denials
opa eval -i tfplan.json -d ec2_schedule_tag_enforcement.rego "data.main.deny" --format pretty

# Full Audit Report
opa eval -i tfplan.json -d ec2_schedule_tag_enforcement.rego "data.main.analysis" --format pretty