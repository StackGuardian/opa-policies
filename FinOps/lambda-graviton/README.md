# AWS Lambda Layer Architecture Enforcement (OPA)

This policy ensures that Lambda Layers are built and tagged for **ARM64 (Graviton)** compatibility. 

## 🛡️ Why this is needed
A Lambda function configured for Graviton (`arm64`) cannot execute binaries within a Layer compiled for `x86_64`. Without this check, you may experience runtime crashes despite a successful deployment.

### Compliance Rule
The `compatible_architectures` list must include `arm64`.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# General Pass/Fail status
opa eval -i tfplan.json -d lambda_graviton_enforcement.rego "data.main.status" --format pretty

# List non-compliant Lambda functions
opa eval -i tfplan.json -d lambda_graviton_enforcement.rego "data.main.deny" --format pretty
```