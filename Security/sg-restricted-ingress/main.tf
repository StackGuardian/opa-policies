# COMPLIANT: Web traffic is public

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/24"
  
}


resource "aws_security_group" "web" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "allow_tls"
  }
}


resource "aws_security_group_rule" "allow_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}

#NON-COMPLIANT: SSH must be restricted to a specific IP
resource "aws_security_group_rule" "bad_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"] # <--- Fails policy
  security_group_id = aws_security_group.web.id
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh_ipv4" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0" # <--- Fails policy
  from_port         = 0
  ip_protocol       = "tcp"
  to_port           = 22
}
