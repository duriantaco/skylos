variable "enabled" {
  default = true
}
locals {
  config = { encrypted = var.enabled }
}
