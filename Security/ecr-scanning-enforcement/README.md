# AWS ECR Image Scanning Enforcement (OPA)

This policy mandates that all private Amazon ECR repositories are configured to automatically scan container images for vulnerabilities upon ingestion.

## 🛡️ Governance Rationale
Unscanned container images create risk by allowing known software vulnerabilities (CVEs) to silently migrate into production execution environments. Automating image analysis at the registration boundary prevents vulnerable artifacts from becoming deployment candidates.

### Compliance Rules
* **Resource Type:** `aws_ecr_repository`
* **Block:** `image_scanning_configuration`
* **Requirement:** `scan_on_push` must be explicitly configured as `true`.
* **Non-Compliant:** Repositories without explicit scanning declarations or configurations explicitly disabled.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d ecr_scanning_enforcement.rego "data.main.status" --format pretty

# View specific non-compliant repositories
opa eval -i tfplan.json -d ecr_scanning_enforcement.rego "data.main.deny" --format pretty
```