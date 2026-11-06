resource "aws_db_instance" "database" {
  provider = aws.unknown_alias
  storage_encrypted = false
}
