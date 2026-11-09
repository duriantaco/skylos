resource "aws_db_instance" "database" {
  replicate_source_db = "arn:aws:rds:us-east-1:000000000000:db:source"
  instance_class = "db.t3.micro"
  storage_encrypted = false
}
