module "ecr" {
  source  = "cloudposse/ecr/aws"
  version = "0.34.0"
  delimiter = "-"
  id_length_limit = 12
  label_key_case = "title"
  label_value_case = "lower"
  name = "ssm-bastion-1"
  namespace = "terraform-ecr"
  enable_lifecycle_policy = true
  image_names = ["devops-test"]
  image_tag_mutability = "IMMUTABLE"
  max_image_count = 500
  scan_images_on_push = true
  use_fullname = true
}