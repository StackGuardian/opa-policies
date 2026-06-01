# AWS Security Group Attachment Enforcement (OPA)

This policy ensures that every Security Group provisioned via Terraform is associated with at least one compute or network resource.

## 🛡️ Governance Rationale
Unattached Security Groups are a form of "configuration drift." They clutter the AWS console and API, making it difficult for security teams to determine which rules are actually in effect. Enforcing attachments ensures that every security rule has a clear, documented purpose and an active target (Instance, ENI, RDS, etc.).

### Compliance Rules
1. **Mandatory Association:** Every `aws_security_group` must be referenced by at least one other resource in the same configuration.
2. **Target Resources:** Valid associations include `vpc_security_group_ids` in EC2/RDS/Lambda or `security_groups` in ALBs.
3. **Non-Compliant:** Security groups created in isolation without any associated resource.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d security_group_attachment_enforcement.rego "data.main.status" --format pretty

# View specific unattached security groups
opa eval -i tfplan.json -d security_group_attachment_enforcement.rego "data.main.deny" --format pretty
```