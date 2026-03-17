# AWS EC2 & EBS gp3 Enforcement Policy (OPA)

This policy mandates the use of **gp3** volumes for all EBS storage. It prevents the use of older **gp2** volumes, which are 20% more expensive and less flexible.



## 💰 Why gp3?
* **Cost:** 20% lower price per GB compared to gp2.
* **Performance:** Baseline 3,000 IOPS and 125 MB/s included regardless of volume size.
* **Flexibility:** Scale IOPS and Throughput independently of storage capacity.

## 📋 Scoped Resources
The policy monitors storage configuration in:
1. `aws_instance` (Root and attached EBS blocks)
2. `aws_launch_template` (EBS mappings for ASG/EKS)
3. `aws_ebs_volume` (Standalone volumes)

---

## 🚀 Usage

### 1. Generate Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check Pass/Fail status
opa eval -i tfplan.json -d ec2_ebs_gp3_only.rego "data.main.status" --format pretty

# List all non-gp3 violations
opa eval -i tfplan.json -d ec2_ebs_gp3_only.rego "data.main.deny" --format pretty