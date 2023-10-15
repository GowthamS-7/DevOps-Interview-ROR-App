terraform {
  backend "s3" {
    bucket         = "tf-remote-state-dev20220615164249902600000003" //module.remote_state.state_bucket
    key            = "terraform-eks/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "92011e9b-fbb3-468b-8900-c8b99cf0b84b" //module.remote_state.kms_key
  }
}