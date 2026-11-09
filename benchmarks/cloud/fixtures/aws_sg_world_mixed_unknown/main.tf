variable "cidr" { type = string }
resource "aws_security_group_rule" "admin" {
  type = "ingress"
  protocol = "6"
  from_port = 20
  to_port = 24
  cidr_blocks = ["0.0.0.0/0", var.cidr]
}
