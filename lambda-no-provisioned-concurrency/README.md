# AWS Lambda Provisioned Concurrency Governance (Cross-Resource)

This policy prevents "Cold Start" mitigation costs in non-production environments. Since `aws_lambda_provisioned_concurrency_config` does not support tags, this policy performs a lookup on the parent `aws_lambda_function`.

## 🛡️ Governance Logic
* **Validation:** Scans the Terraform plan for a matching function name.
* **Requirement:** The parent Lambda function must have the tag `Environment = "Production"`.
* **Action:** Blocks creation or modification of concurrency settings if the environment is Dev/Test/Staging.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Overall Status
opa eval -i tfplan.json -d lambda_no_provisioned_concurrency_nonprod.rego "data.main.status" --format pretty

# List Violations
opa eval -i tfplan.json -d lambda_no_provisioned_concurrency_nonprod.rego "data.main.deny" --format pretty
```