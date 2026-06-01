# GuardDuty Organizational Governance (OPA)

This policy enforces the "Positive Baseline" for threat detection, ensuring GuardDuty is not only enabled but correctly centralized and configured for the entire organization.

## 🛡️ Governance Rationale
GuardDuty is the primary threat-detection primitive. Disabling it or failing to auto-enable it for new accounts creates security blind spots. This policy aligns with tiered requirements:
* **T1:** Basic enablement and 15-minute finding frequency.
* **T2:** Auto-enablement for S3 Protection and Malware Protection across the Org.
* **T3:** Mandatory Runtime Monitoring for high-security accounts.

## 📋 Compliance Rules
1. **Detector:** Must be `enabled` with `FIFTEEN_MINUTES` frequency.
2. **Org Config:** `auto_enable_organization_members` must be `ALL`.
3. **Data Sources:** S3 Logs and Malware Protection must be auto-enabled for the Org.
4. **T3 Feature:** Accounts tagged as `Tier = t3` must include a `RUNTIME_MONITORING` feature.

---

## 🚀 Usage


### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Evaluate overall compliance
opa eval -i tfplan.json -d guardduty_governance_suite.rego "data.main.status" --format pretty

# View detailed Sev-1 violations
opa eval -i tfplan.json -d guardduty_governance_suite.rego "data.main.deny" --format pretty
```
