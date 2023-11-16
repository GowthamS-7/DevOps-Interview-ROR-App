resource "aws_s3_bucket" "dev-bucket" { # main bucket
  bucket = "ror-state-bucket"
  versioning {
    enabled = true
  }
}

# DynamoDB
resource "aws_dynamodb_table" "state_db" {
  name           = "ror-eks-db"
  read_capacity  = 5
  write_capacity = 5

  hash_key = "LockID"
  attribute {
    name = "LockID"
    type = "S"
  }
}