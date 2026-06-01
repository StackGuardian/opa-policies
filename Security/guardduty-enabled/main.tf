# 1. Variable to define the environment tier (T1, T2, or T3)
variable "tier" {
  type        = string
  default     = "T2"
  description = "Security tier (T1, T2, or T3)"
}

# 2. GuardDuty Detector
# Satisfies: enable = true and frequency = FIFTEEN_MINUTES
resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  # T2 Baseline Data Sources
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Tier = var.tier
  }
}

# 3. Organization Configuration (Delegated Admin Account)
# Satisfies: auto_enable_organization_members = ALL
resource "aws_guardduty_organization_configuration" "this" {
  auto_enable_organization_members = "ALL"
  detector_id                      = aws_guardduty_detector.this.id

  datasources {
    s3_logs {
      auto_enable = true
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          auto_enable = true
        }
      }
    }
  }
}

# 4. Runtime Monitoring (T3 Exclusive)
# Satisfies: Runtime Monitoring enabled if Tier is T3
resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  count       = var.tier == "T3" ? 1 : 0
  detector_id = aws_guardduty_detector.this.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"
}