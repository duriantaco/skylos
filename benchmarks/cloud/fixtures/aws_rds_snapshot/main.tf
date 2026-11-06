resource "aws_db_instance" "database" {
  snapshot_identifier = "existing-snapshot"
  instance_class = "db.t3.micro"
  storage_encrypted = false
}
