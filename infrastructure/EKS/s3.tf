resource "aws_s3_bucket" "ror-bucket" { # main bucket
  bucket = "ror-bucket"
  versioning {
    enabled = true
  }
}