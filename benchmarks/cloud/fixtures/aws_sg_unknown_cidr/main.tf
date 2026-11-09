variable "cidrs" {
  type = list(string)
}
resource "aws_security_group_rule" "admin" {
  type = "ingress"
  protocol = "tcp"
  from_port = 3389
  to_port = 3389
  cidr_blocks = var.cidrs
}
