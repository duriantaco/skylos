resource "aws_db_instance" "db" {
  storage_encrypted = local.config.encrypted
}
