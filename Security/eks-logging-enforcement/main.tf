#To satisfy the policy requirements, include all five options within the `enabled_cluster_log_types` attribute block:

resource "aws_eks_cluster" "compliant_cluster" {
  name     = "production-eks-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn

  # Required for Compliance: All 5 log types must be present
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids              = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}