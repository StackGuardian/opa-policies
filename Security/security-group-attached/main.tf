resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # This reference satisfies the OPA policy
  vpc_security_group_ids = [aws_security_group.web_sg.id] 
}