###Compliant Terraform Configurations

#### Modern ALB Example
resource "aws_lb" "compliant_alb" {
  name               = "production-web-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["someid"]

  # Required for Compliance
  access_logs {
    bucket  = "bpost-central-security-logs-bucket"
    prefix  = "alb-logs/web-prod"
    enabled = true
  }
}