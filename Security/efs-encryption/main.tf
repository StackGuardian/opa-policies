# The Authorized Key
resource "aws_kms_key" "Bpost_efs" {
  description = "KMS key for Bpost EFS encryption"
}

# Compliant EFS
resource "aws_efs_file_system" "compliant" {
  creation_token = "bpost-app-data"
  encrypted      = true
  kms_key_id     = aws_kms_key.Bpost_efs.arn # <--- REQUIRED
}