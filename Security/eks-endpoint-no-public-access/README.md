# AWS EKS Cluster Endpoint Privacy Enforcement (OPA)

This policy mandates that the Amazon EKS control plane API endpoint is restricted from public internet access.

## 🛡️ Governance Rationale
Exposing the Kubernetes API server endpoint to the public internet leaves the control plane vulnerable to brute-force credential attacks, zero-day discovery exploits, and unauthorized access attempts. Restricting the endpoint ensures that cluster management traffic remains completely isolated within your VPC or dedicated network paths.

### Compliance Rules
* **Resource Type:** `aws_eks_cluster`
* **Block:** `vpc_config`
* **Requirement:** `endpoint_public_access` must be explicitly configured as `false`.
* **Recommendation:** Combine this with `endpoint_private_access = true` to allow node-to-cluster communication within the internal network.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d eks_endpoint_privacy_enforcement.rego "data.main.status" --format pretty

# View specific non-compliant clusters
opa eval -i tfplan.json -d eks_endpoint_privacy_enforcement.rego "data.main.deny" --format pretty
```