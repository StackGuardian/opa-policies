# AWS Amazon Inspector V2 ECR Scanning Enforcement (OPA)

This policy mandates that Amazon Inspector V2 account-level container image scanning is active for all provisioned AWS environments.

## 🛡️ Governance Rationale
Static "scan-on-push" hooks only evaluate images at a specific point in time. If a zero-day dependency vulnerability is discovered weeks after an image is built, a traditional scanner will miss it. Amazon Inspector V2 fixes this by continuously monitoring registry layers and auto-generating alerts against the container catalog whenever the global CVE index changes.

### Compliance Rules
* **Resource Type:** `aws_inspector2_enabler`
* **Attribute Array:** `resource_types`
* **Requirement:** Must contain the string value `"ECR"`.
* **Non-Compliant:** Resource scopes that limit Inspector monitoring strictly to other targets (like `EC2` or `LAMBDA`) while omitting container registries.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d inspector_ecr_enforcement.rego "data.main.status" --format pretty

# View detailed alignment validation logs
opa eval -i tfplan.json -d inspector_ecr_enforcement.rego "data.main.deny" --format pretty
```