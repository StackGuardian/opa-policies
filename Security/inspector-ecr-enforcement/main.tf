resource "aws_inspector2_enabler" "security_baseline" {
  account_ids = ["123456789012"] # Your AWS Account ID or Organization Root

  # Required for Compliance: Includes ECR alongside other compute horizons
  resource_types = [
    "ECR",
    "EC2",
    "LAMBDA"
  ]
}