# AWS S3 Bucket Key Enforcement Policy (OPA)

This policy mandates the use of **S3 Bucket Keys** when Server-Side Encryption with AWS KMS (SSE-KMS) is used. 

## 💰 FinOps Benefits
By enabling Bucket Keys, S3 reduces the request traffic from S3 to KMS. This can lower your KMS costs by up to **99%** for high-throughput buckets.

### Compliance Rule
If `sse_algorithm` is set to `aws:kms`, then `bucket_key_enabled` must be set to `true`.

---

## 🚀 Usage

### 1. Generate Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Overall Status
opa eval -i tfplan.json -d s3_bucket_key_enforcement.rego "data.main.status" --format pretty

# View Specific Violations
opa eval -i tfplan.json -d s3_bucket_key_enforcement.rego "data.main.deny" --format pretty