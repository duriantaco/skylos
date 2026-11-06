resource "aws_vpc_security_group_ingress_rule" "admin" {
  ip_protocol = "-1"
  cidr_ipv6 = "::/0"
}
