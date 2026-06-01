# AWS EBS Encryption and KMS Enforcement (OPA)

This policy mandates that all EBS volumes are encrypted at rest using a specifically authorized KMS key.

## 🛡️ Governance Rationale
Unencrypted EBS volumes represent a significant data leak risk. By enforcing encryption with a specific Customer Managed Key (CMK), the organization ensures that:
1. **Auditability:** Every disk access is logged via KMS in CloudTrail.
2. **Access Control:** Permissions to decrypt the volume can be managed via Key Policies independently of IAM.
3. **Standards:** Alignment with the Bpost Security Control Framework for data persistence.

### Compliance Rules
* **Encryption:** The `encrypted` attribute must be set to `true`.
* **KMS Key:** The `kms_key_id` must reference the authorized `aws_kms_key.Bpost_ebs` resource.
* **Non-Compliant:** Volumes that are unencrypted or using the default AWS-managed `aws/ebs` key.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall status
opa eval -i tfplan.json -d ebs_encryption_kms_enforcement.rego "data.main.status" --format pretty

# View detailed violations
opa eval -i tfplan.json -d ebs_encryption_kms_enforcement.rego "data.main.deny" --format pretty
```