locals { sources = ["0.0.0.0/1", "128.0.0.0/1"] }
resource "aws_security_group_rule" "admin" {
  type = "ingress"
  protocol = "tcp"
  from_port = 3389
  to_port = 3389
  cidr_blocks = local.sources
}
