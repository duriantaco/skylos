resource "aws_security_group" "admin" {
  ingress {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["10.0.0.0/8"]
  }
}
