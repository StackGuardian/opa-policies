# AWS EBS Encryption by Default Enforcement (OPA)

This policy mandates that account-level EBS encryption by default is enabled in the current AWS region.

## 🛡️ Governance Rationale
Individual EBS volume encryption checks can sometimes miss resources. By enabling encryption by default at the account level, you ensure that every volume provisioned—whether by an EC2 instance, an RDS cluster, or an EKS node—is encrypted at rest using either the default AWS-managed key or a specific CMK.

### Compliance Rule
* **Resource Type:** `aws_ebs_encryption_by_default`
* **Attribute:** `enabled`
* **Requirement:** Must be set to `true`.
* **Impact:** Prevents any unencrypted EBS volumes from being created in the region.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d ebs_default_encryption_enforcement.rego "data.main.status" --format pretty

# View specific violations
opa eval -i tfplan.json -d ebs_default_encryption_enforcement.rego "data.main.deny" --format pretty
```