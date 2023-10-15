variable "vpc_tag_name" {
  type        = string
  description = "Name tag for the VPC"
  default = "eks  vpc tags"
}

variable "route_table_tag_name" {
  type        = string
  default     = "main"
  description = "Route table description"
}

variable "vpc_cidr_block" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block range for vpc"
}

variable "private_subnet_cidr_blocks" {
  type        = list(string)
  default     = ["10.0.0.0/24", "10.0.1.0/24"]
  description = "CIDR block range for the private subnet"
}

variable "public_subnet_cidr_blocks" {
  type = list(string)
  default     = ["10.0.2.0/24", "10.0.3.0/24"]
  description = "CIDR block range for the public subnet"
}

variable "private_subnet_tag_name" {
  type        = string
  default = "Custom Kubernetes cluster private subnet"
  description = "Name tag for the private subnet"
}

variable "public_subnet_tag_name" {
  type        = string
  default = "Custom Kubernetes cluster public subnet"
  description = "Name tag for the public subnet"
}

variable "availability_zones" {
  type  = list(string)
  default = ["us-east-1a", "us-east-1b"]
  description = "List of availability zones for the selected region"
}

variable "region" {
  description = "aws region to deploy to"
  type        = string
}


variable "kms_key_value" {
  description = "kms key value"
  type = string
  default = "arn:aws:kms:us-east-1:076992707442:key/a9f057dd-fdd7-4864-9a5e-26c201cbbb71"
}

variable "cluster_name" {
  type = string
  default = "ror-eks-cluster"
}

variable "bucket_name"{
  default = "ror-s3"
}

variable "db_password" {
  description = "rds db pass"
}
