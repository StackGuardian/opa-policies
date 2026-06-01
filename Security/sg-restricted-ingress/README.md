# AWS Security Group Unrestricted Ingress Enforcement (OPA)

This policy prohibits Security Groups from allowing unrestricted inbound traffic (`0.0.0.0/0` or `::/0`) on any ports other than **80 (HTTP)** and **443 (HTTPS)**.

## 🛡️ Governance Rationale
Unrestricted access to ports like 22 (SSH) or 3389 (RDP) makes instances vulnerable to brute-force attacks and port scanning. By limiting unrestricted traffic to only standard web ports, we significantly reduce the attack surface. All administrative or internal traffic must be restricted to specific CIDR ranges (e.g., Office VPN).

### Compliance Rules
* **Resources Covered:** `aws_vpc_security_group_ingress_rule`, `aws_security_group_rule`, `aws_security_group`.
* **Unrestricted CIDR:** `0.0.0.0/0` and `::/0` are flagged.
* **Authorized Ports:** Only `80` and `443` are permitted for unrestricted CIDRs.
* **Non-Compliant:** * Opening port 22 to `0.0.0.0/0`.
    * Opening a range like `80-443` (which includes restricted ports in between).
    * Opening all ports (`0-65535`) to `0.0.0.0/0`.

---

## 🚀 Usage

### 1. Generate Evaluation Data
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check overall Pass/Fail status
opa eval -i tfplan.json -d sg_unrestricted_ingress_filter.rego "data.main.status" --format pretty

# View detailed violations
opa eval -i tfplan.json -d sg_unrestricted_ingress_filter.rego "data.main.deny" --format pretty
```