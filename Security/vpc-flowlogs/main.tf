resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}



resource "aws_flow_log" "main" {
  traffic_type    = "ALL" # <--- REQUIRED
  vpc_id          = aws_vpc.main.id # <--- REQUIRED
}