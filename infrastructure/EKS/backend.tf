terraform {
  backend "s3" {
    bucket         = "ror-eks-test"
    key            = "terraform-eks/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "ror-eks-cluster"
  }
}