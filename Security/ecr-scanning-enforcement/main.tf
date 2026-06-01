resource "aws_ecr_repository" "compliant_repo" {
  name                 = "production-service-app"
  image_tag_mutability = "MUTABLE"

  # Required for Compliance
  image_scanning_configuration {
    scan_on_push = false
  }
}