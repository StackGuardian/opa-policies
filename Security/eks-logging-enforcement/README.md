# AWS EKS Control Plane Logging Enforcement (OPA)

This policy mandates that all five available Kubernetes control plane log types are explicitly enabled on Amazon EKS clusters.

## 🛡️ Governance Rationale
Without comprehensive control plane logging, security teams lose critical forensic capability. Specifically, missing `audit` or `authenticator` logs means there is no audit trail showing who created pods, modified cluster access, or executed commands inside containers, creating severe blind spots for incident response.

### Compliance Rules
* **Resource Type:** `aws_eks_cluster`
* **Attribute:** `enabled_cluster_log_types`
* **Requirement:** Must contain exactly all five values: `api`, `audit`, `authenticator`, `controllerManager`, and `scheduler`.
* **Non-Compliant:** Clusters where the logging array is omitted or missing one or more types.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d eks_logging_enforcement.rego "data.main.status" --format pretty

# View detailed missing log types per cluster
opa eval -i tfplan.json -d eks_logging_enforcement.rego "data.main.deny" --format pretty
```