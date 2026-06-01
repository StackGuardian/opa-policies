resource "aws_kms_key" "Bpost_ebs" {
  description = "KMS key for Bpost EBS encryption"
}

resource "aws_ebs_volume" "compliant" {
  availability_zone = "eu-central-1a"
  size              = 40
  
  # Requirement 1: Encryption enabled
  encrypted         = true 

  # Requirement 2: Specific KMS key reference
  kms_key_id        = aws_kms_key.Bpost_ebs.arn 
}