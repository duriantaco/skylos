resource "aws_db_instance" "database" {
  count = 0
  storage_encrypted = false
}
