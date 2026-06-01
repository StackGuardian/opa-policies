# AWS VPC Flow Log Enforcement (OPA)

This policy mandates that every Virtual Private Cloud (VPC) has Flow Logs enabled and is configured to capture all traffic types.

## 🛡️ Governance Rationale
VPC Flow Logs provide the primary source of truth for network traffic within a VPC.
* **Security:** Detecting unauthorized connections or data exfiltration.
* **Incident Response:** Analyzing the scope of a breach.
* **Compliance:** Meeting regulatory requirements for network logging.
* **Troubleshooting:** Identifying blocked traffic due to overly restrictive Security Groups or NACLs.

### Compliance Rules
1. **Mandatory Guardrail:** Every `aws_vpc` resource must be referenced by an `aws_flow_log` resource.
2. **Traffic Specification:** The `traffic_type` must be explicitly set to `ALL`.
3. **Non-Compliant:** VPCs without flow logs or logs configured for only `ACCEPT` or `REJECT` traffic.

---

## 🚀 Run Evaluation

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d vpc_flow_log_enforcement.rego "data.main.status" --format pretty

# List specific missing flow logs or incorrect traffic types
opa eval -i tfplan.json -d vpc_flow_log_enforcement.rego "data.main.deny" --format pretty
```