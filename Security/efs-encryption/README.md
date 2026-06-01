# AWS EFS Bpost KMS Encryption Enforcement (OPA)

This policy ensures all Elastic File Systems (EFS) are encrypted using the authorized Bpost EFS KMS key.

## 🛡️ Governance Rationale
To maintain a consistent security posture, all EFS data must be encrypted with the dedicated `aws_kms_key.Bpost_efs` Customer Managed Key. This allows the security team to manage key rotation and access policies centrally.

### Compliance Rules
1. **Encryption Status:** `encrypted` must be set to `true`.
2. **Key Assignment:** `kms_key_id` must reference `aws_kms_key.Bpost_efs.arn`.
3. **Non-Compliant:** Unencrypted file systems or those using the AWS-managed key (`aws/elasticfilesystem`).


---

## 🚀 Run Evaluation

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d efs_encryption_enforcement.rego "data.main.status" --format pretty

# View specific violations
opa eval -i tfplan.json -d efs_encryption_enforcement.rego "data.main.deny" --format pretty
```