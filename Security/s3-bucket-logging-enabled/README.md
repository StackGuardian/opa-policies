# AWS S3 Server Access Logging Enforcement (OPA)

This policy mandates that all Amazon S3 buckets have server access logging enabled to guarantee comprehensive data plane audit trails.

## 🛡️ Governance Rationale
S3 buckets hold critical assets. If a data breach or misconfiguration occurs, server access logs provide the necessary telemetry to identify what data was accessed, by which IAM identity, and at what timestamp. Without logging enabled, security teams have no forensics or visibility into access history.

### Compliance Rules
1. **Mandatory Guardrail:** Every `aws_s3_bucket` must be targeted by an `aws_s3_bucket_logging` resource block in the infrastructure configuration.
2. **Non-Compliant:** Any S3 bucket declared in isolation without a matching logging attachment.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Evaluate compliance baseline
opa eval -i tfplan.json -d s3_logging_enforcement.rego "data.main.status" --format pretty
```