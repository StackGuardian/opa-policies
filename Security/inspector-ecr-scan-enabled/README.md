# AWS Load Balancer Access Logging Enforcement (OPA)

This policy mandates that all Application, Network, and Classic Load Balancers have access logs activated and routed exclusively to the designated central compliance bucket.

## 🛡️ Governance Rationale
Unlogged load balancers represent a severe risk to tracking edge security actions. Access logs provide a detailed record of application interaction points. Enforcing the target destination prevents log fragmentation and ensures data is preserved according to standard regulatory lifecycles.

### Compliance Rules
1. **Scope:** Applies to `aws_lb`, `aws_alb`, and `aws_elb`.
2. **Enablement:** `access_logs.enabled` must be explicitly declared as `true`.
3. **Destination Guardrail:** The `bucket` string must exactly match the defined corporate logging repository name.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d lb_logging_enforcement.rego "data.main.status" --format pretty

# View detailed misconfiguration alerts
opa eval -i tfplan.json -d lb_logging_enforcement.rego "data.main.deny" --format pretty
```