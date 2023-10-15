# VPC Network Setup
resource "aws_vpc" "custom_vpc" {

  cidr_block       = var.vpc_cidr_block
  enable_dns_support = true
  enable_dns_hostnames = true

}

# Create the private subnet
resource "aws_subnet" "private_subnet" {
  count = length(var.availability_zones)
  vpc_id            = aws_vpc.custom_vpc.id
  cidr_block = element(var.private_subnet_cidr_blocks, count.index)
  availability_zone = element(var.availability_zones, count.index)

}

# Create the public subnet
resource "aws_subnet" "public_subnet" {
  count = length(var.availability_zones)
  vpc_id            = "${aws_vpc.custom_vpc.id}"
  cidr_block = element(var.public_subnet_cidr_blocks, count.index)
  availability_zone = element(var.availability_zones, count.index)

  tags = {
    Name = "${var.public_subnet_tag_name}"
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "shared"
    "kubernetes.io/role/elb" = 1
  }

  map_public_ip_on_launch = true
}

# Create IGW for the public subnets
resource "aws_internet_gateway" "igw" {
  vpc_id = "${aws_vpc.custom_vpc.id}"

  tags = {
    Name = "${var.vpc_tag_name}"
  }
}

# Route the public subnet traffic through the IGW
resource "aws_route_table" "main" {
  vpc_id = "${aws_vpc.custom_vpc.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.igw.id}"
  }

  tags = {
    Name = "${var.route_table_tag_name}"
  }
}

# Route table and subnet associations
resource "aws_route_table_association" "internet_access" {
  count = length(var.availability_zones)
  subnet_id      = "${aws_subnet.public_subnet[count.index].id}"
  route_table_id = "${aws_route_table.main.id}"
}

# Create Elastic IP
resource "aws_eip" "main" {
  vpc              = true
}

# Create NAT Gateway
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.main.id
  subnet_id     = aws_subnet.public_subnet[0].id

  tags = {
    Name = "NAT Gateway for Custom Kubernetes Cluster"
  }
}

# Add route to route table
resource "aws_route" "main" {
  route_table_id            = aws_vpc.custom_vpc.default_route_table_id
  destination_cidr_block    = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.main.id
}

# Security group for public subnet resources
resource "aws_security_group" "public_sg" {
  name   = "public-sg"
  vpc_id = aws_vpc.custom_vpc.id

  tags = {
    Name = "public-sg"
  }
}

# Security group traffic rules
## Ingress rule
resource "aws_security_group_rule" "sg_ingress_public_443" {
  security_group_id = aws_security_group.public_sg.id
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "sg_ingress_public_80" {
  security_group_id = aws_security_group.public_sg.id
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

## Egress rule
resource "aws_security_group_rule" "sg_egress_public" {
  security_group_id = aws_security_group.public_sg.id
  type              = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

# Security group for data plane
resource "aws_security_group" "data_plane_sg" {
  name   = "k8s-data-plane-sg"
  vpc_id = aws_vpc.custom_vpc.id

  tags = {
    Name = "k8s-data-plane-sg"
  }
}

# Security group traffic rules
## Ingress rule
resource "aws_security_group_rule" "nodes" {
  description              = "Allow nodes to communicate with each other"
  security_group_id = aws_security_group.data_plane_sg.id
  type              = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "-1"
  cidr_blocks = flatten([var.private_subnet_cidr_blocks, var.public_subnet_cidr_blocks])
}

resource "aws_security_group_rule" "nodes_inbound" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  security_group_id = aws_security_group.data_plane_sg.id
  type              = "ingress"
  from_port   = 1025
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = flatten([var.private_subnet_cidr_blocks])
}

## Egress rule
resource "aws_security_group_rule" "node_outbound" {
  security_group_id = aws_security_group.data_plane_sg.id
  type              = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

# Security group for control plane
resource "aws_security_group" "control_plane_sg" {
  name   = "k8s-control-plane-sg"
  vpc_id = aws_vpc.custom_vpc.id

  tags = {
    Name = "k8s-control-plane-sg"
  }
}

# Security group traffic rules
## Ingress rule
resource "aws_security_group_rule" "control_plane_inbound" {
  security_group_id = aws_security_group.control_plane_sg.id
  type              = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol          = "tcp"
  cidr_blocks = flatten([var.private_subnet_cidr_blocks, var.public_subnet_cidr_blocks])
}

## Egress rule
resource "aws_security_group_rule" "control_plane_outbound" {
  security_group_id = aws_security_group.control_plane_sg.id
  type              = "egress"
  from_port   = 0
  to_port     = 65535
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}


#######EKS_Creation########

provider "aws" {
  region = local.region
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1alpha1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_id]
  }
}

locals {
  name            = var.cluster_name
  cluster_version = "1.22"
  region          = "us-east-1"
}

################################################################################
# EKS Module
################################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 18.0"

  cluster_name                    = local.name
  cluster_version                 = local.cluster_version
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true

  # IPV6
  cluster_ip_family = "ipv4"

  # We are using the IRSA created below for permissions
  # However, we have to deploy with the policy attached FIRST (when creating a fresh cluster)
  # and then turn this off after the cluster/node group is created. Without this initial policy,
  # the VPC CNI fails to assign IPs and nodes cannot join the cluster
  # See https://github.com/aws/containers-roadmap/issues/1666 for more context
  # TODO - remove this policy once AWS releases a managed version similar to AmazonEKS_CNI_Policy (IPv4)
  create_cni_ipv6_iam_policy = false

  cluster_addons = {
    coredns = {
      resolve_conflicts = "OVERWRITE"
    }
    kube-proxy = {}
  }

  cluster_encryption_config = [
    {
      provider_key_arn = aws_kms_key.eks.arn
      resources        = ["secrets"]
    }
  ]

  cluster_tags = {
    # This should not affect the name of the cluster primary security group
    # Ref: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2006
    # Ref: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2008
    Name = local.name
  }

  vpc_id     = data.terraform_remote_state.environment_setup.outputs.vpc_id
  subnet_ids = split(",", data.terraform_remote_state.environment_setup.outputs.private_subnets)

  manage_aws_auth_configmap = true
  create_aws_auth_configmap = false
  aws_auth_roles            = [
    {
      rolearn  = "arn:aws:iam::076992707442:role/k8s-admin-role"
      username = "k8s-admin/{{SessionName}}"
      groups   = ["system:masters"]
    }
  ]

  cluster_additional_security_group_ids   = [aws_security_group.additional.id]
  # Extend cluster security group rules
  cluster_security_group_additional_rules = {
    egress_nodes_ephemeral_ports_tcp = {
      description                = "To node 1025-65535"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "egress"
      source_node_security_group = true
    }
  }

  # Extend node-to-node security group rules
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    egress_all = {
      description = "Node all egress"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "egress"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  eks_managed_node_group_defaults = {
    ami_type       = "AL2_x86_64"
    instance_types = ["t3.medium"]

    # We are using the IRSA created below for permissions
    # However, we have to deploy with the policy attached FIRST (when creating a fresh cluster)
    # and then turn this off after the cluster/node group is created. Without this initial policy,
    # the VPC CNI fails to assign IPs and nodes cannot join the cluster
    # See https://github.com/aws/containers-roadmap/issues/1666 for more context
    iam_role_attach_cni_policy = true
  }

  eks_managed_node_groups = {
    # Default node group - as provided by AWS EKS
    default_node_group = {
      # By default, the module creates a launch template to ensure tags are propagated to instances, etc.,
      # so we need to disable it to use the default template provided by the AWS EKS managed node group service
      create_launch_template = false
      launch_template_name   = ""
      desired_size           = 2
      min_size               = 1
      max_size               = 10

      disk_size = 50

      # Remote access cannot be specified with a launch template
      remote_access = {
        ec2_ssh_key               = aws_key_pair.this.key_name
        source_security_group_ids = [aws_security_group.remote_access.id]
      }
    }
  }

  tags = local.tags
}

################################################################################
# Supporting Resources
################################################################################

resource "aws_security_group" "additional" {
  name_prefix = "${local.name}-additional"
  vpc_id      = data.terraform_remote_state.environment_setup.outputs.vpc_id

  ingress {
    description = "IngressSSHInt"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [
      "10.0.0.0/16",
    ]
  }

  ingress {
    description = "IngressHttpInt"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [
      "10.0.0.0/16",
    ]
  }

  ingress {
    description = "IngressHttpsInt"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [
      "10.0.0.0/16",
    ]
  }

}

resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

}

resource "aws_kms_key" "ebs" {
  description             = "Customer managed key to encrypt EKS managed node group volumes"
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.ebs.json
  enable_key_rotation     = true
  tags                    = local.tags
}

# This policy is required for the KMS key used for EKS root volumes, so the cluster is allowed to enc/dec/attach encrypted EBS volumes
data "aws_iam_policy_document" "ebs" {
  # Copy of default KMS policy that lets you manage it
  statement {
    sid       = "Enable IAM User Permissions"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.terraform_remote_state.environment_setup.outputs.aws_account_id}:root"]
    }
  }

  # Required for EKS
  statement {
    sid     = "Allow service-linked role use of the CMK"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [
        "arn:aws:iam::${data.terraform_remote_state.environment_setup.outputs.aws_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
        # required for the ASG to manage encrypted volumes for nodes
        module.eks.cluster_iam_role_arn,
        # required for the cluster / persistentvolume-controller to create encrypted PVCs
      ]
    }
  }

  statement {
    sid       = "Allow attachment of persistent resources"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [
        "arn:aws:iam::${data.terraform_remote_state.environment_setup.outputs.aws_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
        # required for the ASG to manage encrypted volumes for nodes
        module.eks.cluster_iam_role_arn,
        # required for the cluster / persistentvolume-controller to create encrypted PVCs
      ]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "eks-lb-attach" {
  policy_arn = aws_iam_policy.eks-lb-role-policy.arn
  role       = module.eks.cluster_iam_role_name
}

resource "aws_iam_policy" "eks-lb-role-policy" {
  name        = "eks_lb_policy"
  path        = "/"
  description = "Policy for Kubernetes role assumed by the nodes to allow LB management"

  policy = data.aws_iam_policy_document.eks-lb.json
}

# This policy is created to allow the usage of the AWS Load Balancer Controller
data "aws_iam_policy_document" "eks-lb" {
  statement {
    sid       = "EnableLBManage"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["elasticloadbalancing.amazonaws.com"]
      variable = "iam:AWSServiceName"
    }
  }

  statement {
    sid     = "EnableEC2Manage"
    actions = [
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeVpcs",
      "ec2:DescribeVpcPeeringConnections",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeTags",
      "ec2:GetCoipPoolUsage",
      "ec2:DescribeCoipPools",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeListenerCertificates",
      "elasticloadbalancing:DescribeSSLPolicies",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeTags"
    ]
    resources = ["*"]
  }
  statement {
    sid     = "EnableSecManage"
    actions = [
      "cognito-idp:DescribeUserPoolClient",
      "acm:ListCertificates",
      "acm:DescribeCertificate",
      "iam:ListServerCertificates",
      "iam:GetServerCertificate",
      "waf-regional:GetWebACL",
      "waf-regional:GetWebACLForResource",
      "waf-regional:AssociateWebACL",
      "waf-regional:DisassociateWebACL",
      "wafv2:GetWebACL",
      "wafv2:GetWebACLForResource",
      "wafv2:AssociateWebACL",
      "wafv2:DisassociateWebACL",
      "shield:GetSubscriptionState",
      "shield:DescribeProtection",
      "shield:CreateProtection",
      "shield:DeleteProtection"
    ]
    resources = ["*"]
  }
  statement {
    sid     = "EnableSGManage"
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress", "ec2:CreateSecurityGroup", "elasticloadbalancing:SetWebAcl",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:AddListenerCertificates",
      "elasticloadbalancing:RemoveListenerCertificates",
      "elasticloadbalancing:ModifyRule", "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:DeleteRule", "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DeleteSecurityGroup", "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateTargetGroup", "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:SetIpAddressType",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:DeleteTargetGroup"
    ]
    resources = ["*"]
  }
  statement {
    sid     = "TagSG"
    actions = [
      "ec2:CreateTags",
      "ec2:DeleteTags"
    ]
    resources = ["arn:aws:ec2:*:*:security-group/*"]
  }
  statement {
    sid     = "TagLB"
    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets"
    ]
    resources = [
      "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
      "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
      "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
    ]
  }
}


# This is based on the LT that EKS would create if no custom one is specified (aws ec2 describe-launch-template-versions --launch-template-id xxx)
# there are several more options one could set but you probably dont need to modify them
# you can take the default and add your custom AMI and/or custom tags
#
# Trivia: AWS transparently creates a copy of your LaunchTemplate and actually uses that copy then for the node group. If you DONT use a custom AMI,
# then the default user-data for bootstrapping a cluster is merged in the copy.

resource "aws_launch_template" "external" {
  name_prefix            = "external-eks-ex-"
  description            = "EKS managed node group external launch template"
  update_default_version = true

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 100
      volume_type           = "gp2"
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  # Disabling due to https://github.com/hashicorp/terraform-provider-aws/issues/23766
  # network_interfaces {
  #   associate_public_ip_address = false
  #   delete_on_termination       = true
  # }

  # if you want to use a custom AMI
  # image_id      = var.ami_id

  # If you use a custom AMI, you need to supply via user-data, the bootstrap script as EKS DOESNT merge its managed user-data then
  # you can add more than the minimum code you see in the template, e.g. install SSM agent, see https://github.com/aws/containers-roadmap/issues/593#issuecomment-577181345
  # (optionally you can use https://registry.terraform.io/providers/hashicorp/cloudinit/latest/docs/data-sources/cloudinit_config to render the script, example: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/997#issuecomment-705286151)
  # user_data = base64encode(data.template_file.launch_template_userdata.rendered)

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name      = "external_lt"
      CustomTag = "Instance custom tag"
    }
  }

  tag_specifications {
    resource_type = "volume"

    tags = {
      CustomTag = "Volume custom tag"
    }
  }

  tag_specifications {
    resource_type = "network-interface"

    tags = {
      CustomTag = "EKS example"
    }
  }

  tags = {
    CustomTag = "Launch template custom tag"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "tls_private_key" "this" {
  algorithm = "RSA"
}

resource "aws_key_pair" "this" {
  key_name_prefix = local.name
  public_key      = tls_private_key.this.public_key_openssh

}

resource "aws_security_group" "remote_access" {
  name_prefix = "${local.name}-remote-access"
  description = "Allow remote SSH access"
  vpc_id      = data.terraform_remote_state.environment_setup.outputs.vpc_id

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "All Egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

data "aws_iam_policy_document" "k8s-admin-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::076992707442:root"]
    }
  }
}

resource "aws_iam_policy" "k8s-admin-role-policy" {
  name        = "k8s_admin_policy"
  path        = "/"
  description = "Policy for Kubernetes Admin role that is assumed to manage the nodes"

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        "Sid"    = "EKSRead",
        "Effect" = "Allow",
        "Action" = [
          "eks:ListFargateProfiles",
          "eks:ListNodegroups",
          "eks:DescribeFargateProfile",
          "eks:ListTagsForResource",
          "eks:DescribeIdentityProviderConfig",
          "eks:ListUpdates",
          "eks:DescribeUpdate",
          "eks:AccessKubernetesApi",
          "eks:ListAddons",
          "eks:DescribeCluster",
          "eks:ListIdentityProviderConfigs",
          "eks:DescribeAddon"
        ],
        "Resource" = [
          "arn:aws:eks:*:076992707442:fargateprofile/*/*/*",
          "arn:aws:eks:*:076992707442:addon/*/*/*",
          "arn:aws:eks:*:076992707442:identityproviderconfig/*/*/*/*",
          "arn:aws:eks:*:076992707442:cluster/*"
        ]
      },
      {
        "Sid"    = "EKSGeneral",
        "Effect" = "Allow",
        "Action" = [
          "eks:ListClusters",
          "eks:DescribeAddonVersions"
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_role" "k8s-admin-role" {
  name               = "k8s-admin-role"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.k8s-admin-assume-role-policy.json
}

resource "aws_iam_role_policy_attachment" "k8s-admin-role-eks-perms" {
  role       = aws_iam_role.k8s-admin-role.name
  policy_arn = aws_iam_policy.k8s-admin-role-policy.arn
}


######ECR_Creation#####

module "ecr" {
  source  = "cloudposse/ecr/aws"
  version = "0.34.0"
  delimiter = "-"
  enabled = true
  encryption_configuration = {
    encryption_type = "KMS"
    kms_key = "arn:aws:kms:us-east-1:076992707442:key/a9f057dd-fdd7-4864-9a5e-26c201cbbb71"
  }
  id_length_limit = 12
  label_key_case = "title"
  label_value_case = "lower"
  name = "ssm-bastion-1"
  namespace = "terraform-ecr"
  enable_lifecycle_policy = true
  image_names = ["devops-test"]
  image_tag_mutability = "IMMUTABLE"
  max_image_count = 500
  principals_full_access = [module.eks.cluster_iam_role_arn, module.eks.eks_managed_node_groups["default_node_group"].iam_role_arn]
  principals_lambda = []
  principals_readonly_access = ["arn:aws:iam::076992707442:role/k8s-admin-role"]
  scan_images_on_push = true
  use_fullname = true
}

####S3_CREATION#####

resource "aws_s3_bucket" "ror-s3" {
  bucket = var.bucket_name

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "alias/aws/s3"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_acl" "ror-s3-acl" {
  bucket = aws_s3_bucket.ror-s3.id
  acl    = "private"
}

####RDS_CREATION####

resource "aws_db_instance" "my_rds_instance" {
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "13.3"
  instance_class       = "db.t3.micro"
  db_name              = "railsdb"
  username             = "dbuser"
  password             = var.db_password
  parameter_group_name = "default.postgres13"
  skip_final_snapshot  = true

  vpc_security_group_ids = [aws_security_group.rds_security_group.id]
  db_subnet_group_name     = aws_db_subnet_group.rails_db_subnet_group.name

}

resource "aws_security_group" "rds_security_group" {
  vpc_id = aws_vpc.main_vpc.id  
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "rails_db_subnet_group" {
  name       = "rails-db-subnet-group"
  subnet_ids = aws_subnet.private_subnet[*].id
}


####Nginx_ingress_controller&loadbalancer_Creation#####

resource "kubernetes_manifest" "namespace_ingress_nginx" {
  manifest = {
    "apiVersion" = "v1"
    "kind" = "Namespace"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
      }
      "name" = "ingress-nginx"
    }
  }
}

resource "kubernetes_manifest" "serviceaccount_ingress_nginx_ingress_nginx" {
  manifest = {
    "apiVersion" = "v1"
    "automountServiceAccountToken" = true
    "kind" = "ServiceAccount"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx"
      "namespace" = "ingress-nginx"
    }
  }
}

resource "kubernetes_manifest" "serviceaccount_ingress_nginx_ingress_nginx_admission" {
  manifest = {
    "apiVersion" = "v1"
    "kind" = "ServiceAccount"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "admission-webhook"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-admission"
      "namespace" = "ingress-nginx"
    }
  }
}

resource "kubernetes_manifest" "role_ingress_nginx_ingress_nginx" {
  manifest = {
    "apiVersion" = "rbac.authorization.k8s.io/v1"
    "kind" = "Role"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx"
      "namespace" = "ingress-nginx"
    }
    "rules" = [
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "namespaces",
        ]
        "verbs" = [
          "get",
        ]
      },
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "configmaps",
          "pods",
          "secrets",
          "endpoints",
        ]
        "verbs" = [
          "get",
          "list",
          "watch",
        ]
      },
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "services",
        ]
        "verbs" = [
          "get",
          "list",
          "watch",
        ]
      },
      {
        "apiGroups" = [
          "networking.k8s.io",
        ]
        "resources" = [
          "ingresses",
        ]
        "verbs" = [
          "get",
          "list",
          "watch",
        ]
      },
      {
        "apiGroups" = [
          "networking.k8s.io",
        ]
        "resources" = [
          "ingresses/status",
        ]
        "verbs" = [
          "update",
        ]
      },
      {
        "apiGroups" = [
          "networking.k8s.io",
        ]
        "resources" = [
          "ingressclasses",
        ]
        "verbs" = [
          "get",
          "list",
          "watch",
        ]
      },
      {
        "apiGroups" = [
          "",
        ]
        "resourceNames" = [
          "ingress-controller-leader",
        ]
        "resources" = [
          "configmaps",
        ]
        "verbs" = [
          "get",
          "update",
        ]
      },
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "configmaps",
        ]
        "verbs" = [
          "create",
        ]
      },
      {
        "apiGroups" = [
          "coordination.k8s.io",
        ]
        "resourceNames" = [
          "ingress-controller-leader",
        ]
        "resources" = [
          "leases",
        ]
        "verbs" = [
          "get",
          "update",
        ]
      },
      {
        "apiGroups" = [
          "coordination.k8s.io",
        ]
        "resources" = [
          "leases",
        ]
        "verbs" = [
          "create",
        ]
      },
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "events",
        ]
        "verbs" = [
          "create",
          "patch",
        ]
      },
    ]
  }
}

resource "kubernetes_manifest" "role_ingress_nginx_ingress_nginx_admission" {
  manifest = {
    "apiVersion" = "rbac.authorization.k8s.io/v1"
    "kind" = "Role"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "admission-webhook"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-admission"
      "namespace" = "ingress-nginx"
    }
    "rules" = [
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "secrets",
        ]
        "verbs" = [
          "get",
          "create",
        ]
      },
    ]
  }
}

resource "kubernetes_manifest" "clusterrole_ingress_nginx" {
  manifest = {
    "apiVersion" = "rbac.authorization.k8s.io/v1"
    "kind" = "ClusterRole"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx"
    }
    "rules" = [
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "configmaps",
          "endpoints",
          "nodes",
          "pods",
          "secrets",
          "namespaces",
        ]
        "verbs" = [
          "list",
          "watch",
        ]
      },
      {
        "apiGroups" = [
          "coordination.k8s.io",
        ]
        "resources" = [
          "leases",
        ]
        "verbs" = [
          "list",
          "watch",
        ]
      },
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "nodes",
        ]
        "verbs" = [
          "get",
        ]
      },
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "services",
        ]
        "verbs" = [
          "get",
          "list",
          "watch",
        ]
      },
      {
        "apiGroups" = [
          "networking.k8s.io",
        ]
        "resources" = [
          "ingresses",
        ]
        "verbs" = [
          "get",
          "list",
          "watch",
        ]
      },
      {
        "apiGroups" = [
          "",
        ]
        "resources" = [
          "events",
        ]
        "verbs" = [
          "create",
          "patch",
        ]
      },
      {
        "apiGroups" = [
          "networking.k8s.io",
        ]
        "resources" = [
          "ingresses/status",
        ]
        "verbs" = [
          "update",
        ]
      },
      {
        "apiGroups" = [
          "networking.k8s.io",
        ]
        "resources" = [
          "ingressclasses",
        ]
        "verbs" = [
          "get",
          "list",
          "watch",
        ]
      },
    ]
  }
}

resource "kubernetes_manifest" "clusterrole_ingress_nginx_admission" {
  manifest = {
    "apiVersion" = "rbac.authorization.k8s.io/v1"
    "kind" = "ClusterRole"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "admission-webhook"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-admission"
    }
    "rules" = [
      {
        "apiGroups" = [
          "admissionregistration.k8s.io",
        ]
        "resources" = [
          "validatingwebhookconfigurations",
        ]
        "verbs" = [
          "get",
          "update",
        ]
      },
    ]
  }
}

resource "kubernetes_manifest" "rolebinding_ingress_nginx_ingress_nginx" {
  manifest = {
    "apiVersion" = "rbac.authorization.k8s.io/v1"
    "kind" = "RoleBinding"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx"
      "namespace" = "ingress-nginx"
    }
    "roleRef" = {
      "apiGroup" = "rbac.authorization.k8s.io"
      "kind" = "Role"
      "name" = "ingress-nginx"
    }
    "subjects" = [
      {
        "kind" = "ServiceAccount"
        "name" = "ingress-nginx"
        "namespace" = "ingress-nginx"
      },
    ]
  }
}

resource "kubernetes_manifest" "rolebinding_ingress_nginx_ingress_nginx_admission" {
  manifest = {
    "apiVersion" = "rbac.authorization.k8s.io/v1"
    "kind" = "RoleBinding"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "admission-webhook"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-admission"
      "namespace" = "ingress-nginx"
    }
    "roleRef" = {
      "apiGroup" = "rbac.authorization.k8s.io"
      "kind" = "Role"
      "name" = "ingress-nginx-admission"
    }
    "subjects" = [
      {
        "kind" = "ServiceAccount"
        "name" = "ingress-nginx-admission"
        "namespace" = "ingress-nginx"
      },
    ]
  }
}

resource "kubernetes_manifest" "clusterrolebinding_ingress_nginx" {
  manifest = {
    "apiVersion" = "rbac.authorization.k8s.io/v1"
    "kind" = "ClusterRoleBinding"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx"
    }
    "roleRef" = {
      "apiGroup" = "rbac.authorization.k8s.io"
      "kind" = "ClusterRole"
      "name" = "ingress-nginx"
    }
    "subjects" = [
      {
        "kind" = "ServiceAccount"
        "name" = "ingress-nginx"
        "namespace" = "ingress-nginx"
      },
    ]
  }
}

resource "kubernetes_manifest" "clusterrolebinding_ingress_nginx_admission" {
  manifest = {
    "apiVersion" = "rbac.authorization.k8s.io/v1"
    "kind" = "ClusterRoleBinding"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "admission-webhook"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-admission"
    }
    "roleRef" = {
      "apiGroup" = "rbac.authorization.k8s.io"
      "kind" = "ClusterRole"
      "name" = "ingress-nginx-admission"
    }
    "subjects" = [
      {
        "kind" = "ServiceAccount"
        "name" = "ingress-nginx-admission"
        "namespace" = "ingress-nginx"
      },
    ]
  }
}

resource "kubernetes_manifest" "configmap_ingress_nginx_ingress_nginx_controller" {
  manifest = {
    "apiVersion" = "v1"
    "data" = {
      "allow-snippet-annotations" = "true"
      "http-snippet" = <<-EOT
      server {
        listen 2443;
        return 308 https://$host$request_uri;
      }
      
      EOT
      "proxy-real-ip-cidr" = "10.0.0.0/16"
      "use-forwarded-headers" = "true"
    }
    "kind" = "ConfigMap"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-controller"
      "namespace" = "ingress-nginx"
    }
  }
}

resource "kubernetes_manifest" "service_ingress_nginx_ingress_nginx_controller" {
  manifest = {
    "apiVersion" = "v1"
    "kind" = "Service"
    "metadata" = {
      "annotations" = {
        "service.beta.kubernetes.io/aws-load-balancer-connection-idle-timeout" = "60"
        "service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled" = "true"
        "service.beta.kubernetes.io/aws-load-balancer-ssl-cert" = "arn:aws:acm:us-east-1:076992707442:certificate/bb2bc5dc-6786-41b5-a72b-a949a3e444aa"
        "service.beta.kubernetes.io/aws-load-balancer-ssl-ports" = "https"
        "service.beta.kubernetes.io/aws-load-balancer-type" = "nlb"
      }
      "labels" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-controller"
      "namespace" = "ingress-nginx"
    }
    "spec" = {
      "externalTrafficPolicy" = "Cluster"
      "ipFamilies" = [
        "IPv4",
      ]
      "ipFamilyPolicy" = "SingleStack"
      "ports" = [
        {
          "appProtocol" = "http"
          "name" = "http"
          "port" = 80
          "protocol" = "TCP"
          "targetPort" = "tohttps"
        },
        {
          "appProtocol" = "https"
          "name" = "https"
          "port" = 443
          "protocol" = "TCP"
          "targetPort" = "http"
        },
      ]
      "selector" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
      }
      "type" = "LoadBalancer"
    }
  }
}

resource "kubernetes_manifest" "service_ingress_nginx_ingress_nginx_controller_admission" {
  manifest = {
    "apiVersion" = "v1"
    "kind" = "Service"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-controller-admission"
      "namespace" = "ingress-nginx"
    }
    "spec" = {
      "ports" = [
        {
          "appProtocol" = "https"
          "name" = "https-webhook"
          "port" = 443
          "targetPort" = "webhook"
        },
      ]
      "selector" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
      }
      "type" = "ClusterIP"
    }
  }
}

resource "kubernetes_manifest" "deployment_ingress_nginx_ingress_nginx_controller" {
  manifest = {
    "apiVersion" = "apps/v1"
    "kind" = "Deployment"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-controller"
      "namespace" = "ingress-nginx"
    }
    "spec" = {
      "minReadySeconds" = 0
      "replicas" = 2
      "revisionHistoryLimit" = 10
      "selector" = {
        "matchLabels" = {
          "app.kubernetes.io/component" = "controller"
          "app.kubernetes.io/instance" = "ingress-nginx"
          "app.kubernetes.io/name" = "ingress-nginx"
        }
      }
      "template" = {
        "metadata" = {
          "labels" = {
            "app.kubernetes.io/component" = "controller"
            "app.kubernetes.io/instance" = "ingress-nginx"
            "app.kubernetes.io/name" = "ingress-nginx"
          }
        }
        "spec" = {
          "containers" = [
            {
              "args" = [
                "/nginx-ingress-controller",
                "--publish-service=$(POD_NAMESPACE)/ingress-nginx-controller",
                "--election-id=ingress-controller-leader",
                "--controller-class=k8s.io/ingress-nginx",
                "--ingress-class=nginx",
                "--configmap=$(POD_NAMESPACE)/ingress-nginx-controller",
                "--validating-webhook=:8443",
                "--validating-webhook-certificate=/usr/local/certificates/cert",
                "--validating-webhook-key=/usr/local/certificates/key",
              ]
              "env" = [
                {
                  "name" = "POD_NAME"
                  "valueFrom" = {
                    "fieldRef" = {
                      "fieldPath" = "metadata.name"
                    }
                  }
                },
                {
                  "name" = "POD_NAMESPACE"
                  "valueFrom" = {
                    "fieldRef" = {
                      "fieldPath" = "metadata.namespace"
                    }
                  }
                },
                {
                  "name" = "LD_PRELOAD"
                  "value" = "/usr/local/lib/libmimalloc.so"
                },
              ]
              "image" = "registry.k8s.io/ingress-nginx/controller:v1.3.0@sha256:d1707ca76d3b044ab8a28277a2466a02100ee9f58a86af1535a3edf9323ea1b5"
              "imagePullPolicy" = "IfNotPresent"
              "lifecycle" = {
                "preStop" = {
                  "exec" = {
                    "command" = [
                      "/wait-shutdown",
                    ]
                  }
                }
              }
              "livenessProbe" = {
                "failureThreshold" = 5
                "httpGet" = {
                  "path" = "/healthz"
                  "port" = 10254
                  "scheme" = "HTTP"
                }
                "initialDelaySeconds" = 10
                "periodSeconds" = 10
                "successThreshold" = 1
                "timeoutSeconds" = 1
              }
              "name" = "controller"
              "ports" = [
                {
                  "containerPort" = 80
                  "name" = "http"
                  "protocol" = "TCP"
                },
                {
                  "containerPort" = 80
                  "name" = "https"
                  "protocol" = "TCP"
                },
                {
                  "containerPort" = 2443
                  "name" = "tohttps"
                  "protocol" = "TCP"
                },
                {
                  "containerPort" = 8443
                  "name" = "webhook"
                  "protocol" = "TCP"
                },
              ]
              "readinessProbe" = {
                "failureThreshold" = 3
                "httpGet" = {
                  "path" = "/healthz"
                  "port" = 10254
                  "scheme" = "HTTP"
                }
                "initialDelaySeconds" = 10
                "periodSeconds" = 10
                "successThreshold" = 1
                "timeoutSeconds" = 1
              }
              "resources" = {
                "requests" = {
                  "cpu" = "100m"
                  "memory" = "90Mi"
                }
              }
              "securityContext" = {
                "allowPrivilegeEscalation" = true
                "capabilities" = {
                  "add" = [
                    "NET_BIND_SERVICE",
                  ]
                  "drop" = [
                    "ALL",
                  ]
                }
                "runAsUser" = 101
              }
              "volumeMounts" = [
                {
                  "mountPath" = "/usr/local/certificates/"
                  "name" = "webhook-cert"
                  "readOnly" = true
                },
              ]
            },
          ]
          "dnsPolicy" = "ClusterFirst"
          "nodeSelector" = {
            "kubernetes.io/os" = "linux"
          }
          "serviceAccountName" = "ingress-nginx"
          "terminationGracePeriodSeconds" = 300
          "volumes" = [
            {
              "name" = "webhook-cert"
              "secret" = {
                "secretName" = "ingress-nginx-admission"
              }
            },
          ]
        }
      }
    }
  }
}

resource "kubernetes_manifest" "job_ingress_nginx_ingress_nginx_admission_create" {
  manifest = {
    "apiVersion" = "batch/v1"
    "kind" = "Job"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "admission-webhook"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-admission-create"
      "namespace" = "ingress-nginx"
    }
    "spec" = {
      "template" = {
        "metadata" = {
          "labels" = {
            "app.kubernetes.io/component" = "admission-webhook"
            "app.kubernetes.io/instance" = "ingress-nginx"
            "app.kubernetes.io/name" = "ingress-nginx"
            "app.kubernetes.io/part-of" = "ingress-nginx"
            "app.kubernetes.io/version" = "1.3.0"
          }
          "name" = "ingress-nginx-admission-create"
        }
        "spec" = {
          "containers" = [
            {
              "args" = [
                "create",
                "--host=ingress-nginx-controller-admission,ingress-nginx-controller-admission.$(POD_NAMESPACE).svc",
                "--namespace=$(POD_NAMESPACE)",
                "--secret-name=ingress-nginx-admission",
              ]
              "env" = [
                {
                  "name" = "POD_NAMESPACE"
                  "valueFrom" = {
                    "fieldRef" = {
                      "fieldPath" = "metadata.namespace"
                    }
                  }
                },
              ]
              "image" = "registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.3.0@sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47"
              "imagePullPolicy" = "IfNotPresent"
              "name" = "create"
              "securityContext" = {
                "allowPrivilegeEscalation" = false
              }
            },
          ]
          "nodeSelector" = {
            "kubernetes.io/os" = "linux"
          }
          "restartPolicy" = "OnFailure"
          "securityContext" = {
            "fsGroup" = 2000
            "runAsNonRoot" = true
            "runAsUser" = 2000
          }
          "serviceAccountName" = "ingress-nginx-admission"
        }
      }
    }
  }
}

resource "kubernetes_manifest" "job_ingress_nginx_ingress_nginx_admission_patch" {
  manifest = {
    "apiVersion" = "batch/v1"
    "kind" = "Job"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "admission-webhook"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-admission-patch"
      "namespace" = "ingress-nginx"
    }
    "spec" = {
      "template" = {
        "metadata" = {
          "labels" = {
            "app.kubernetes.io/component" = "admission-webhook"
            "app.kubernetes.io/instance" = "ingress-nginx"
            "app.kubernetes.io/name" = "ingress-nginx"
            "app.kubernetes.io/part-of" = "ingress-nginx"
            "app.kubernetes.io/version" = "1.3.0"
          }
          "name" = "ingress-nginx-admission-patch"
        }
        "spec" = {
          "containers" = [
            {
              "args" = [
                "patch",
                "--webhook-name=ingress-nginx-admission",
                "--namespace=$(POD_NAMESPACE)",
                "--patch-mutating=false",
                "--secret-name=ingress-nginx-admission",
                "--patch-failure-policy=Fail",
              ]
              "env" = [
                {
                  "name" = "POD_NAMESPACE"
                  "valueFrom" = {
                    "fieldRef" = {
                      "fieldPath" = "metadata.namespace"
                    }
                  }
                },
              ]
              "image" = "registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.3.0@sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47"
              "imagePullPolicy" = "IfNotPresent"
              "name" = "patch"
              "securityContext" = {
                "allowPrivilegeEscalation" = false
              }
            },
          ]
          "nodeSelector" = {
            "kubernetes.io/os" = "linux"
          }
          "restartPolicy" = "OnFailure"
          "securityContext" = {
            "fsGroup" = 2000
            "runAsNonRoot" = true
            "runAsUser" = 2000
          }
          "serviceAccountName" = "ingress-nginx-admission"
        }
      }
    }
  }
}

resource "kubernetes_manifest" "ingressclass_nginx" {
  manifest = {
    "apiVersion" = "networking.k8s.io/v1"
    "kind" = "IngressClass"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "controller"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "nginx"
    }
    "spec" = {
      "controller" = "k8s.io/ingress-nginx"
    }
  }
}

resource "kubernetes_manifest" "validatingwebhookconfiguration_ingress_nginx_admission" {
  manifest = {
    "apiVersion" = "admissionregistration.k8s.io/v1"
    "kind" = "ValidatingWebhookConfiguration"
    "metadata" = {
      "labels" = {
        "app.kubernetes.io/component" = "admission-webhook"
        "app.kubernetes.io/instance" = "ingress-nginx"
        "app.kubernetes.io/name" = "ingress-nginx"
        "app.kubernetes.io/part-of" = "ingress-nginx"
        "app.kubernetes.io/version" = "1.3.0"
      }
      "name" = "ingress-nginx-admission"
    }
    "webhooks" = [
      {
        "admissionReviewVersions" = [
          "v1",
        ]
        "clientConfig" = {
          "service" = {
            "name" = "ingress-nginx-controller-admission"
            "namespace" = "ingress-nginx"
            "path" = "/networking/v1/ingresses"
          }
        }
        "failurePolicy" = "Fail"
        "matchPolicy" = "Equivalent"
        "name" = "validate.nginx.ingress.kubernetes.io"
        "rules" = [
          {
            "apiGroups" = [
              "networking.k8s.io",
            ]
            "apiVersions" = [
              "v1",
            ]
            "operations" = [
              "CREATE",
              "UPDATE",
            ]
            "resources" = [
              "ingresses",
            ]
          },
        ]
        "sideEffects" = "None"
      },
    ]
  }
}


#####APPLICATION_DEPLOYMENT#######

resource "kubernetes_manifest" "deployment_ror_application" {
  manifest = {
    "apiVersion" = "apps/v1"
    "kind" = "Deployment"
    "metadata" = {
      "labels" = {
        "app" = "ror-application"
      }
      "name" = "ror-application"
    }
    "spec" = {
      "replicas" = 2
      "selector" = {
        "matchLabels" = {
          "app" = "ror-application"
        }
      }
      "template" = {
        "metadata" = {
          "labels" = {
            "app" = "ror-application"
          }
        }
        "spec" = {
          "containers" = [
            {
              "env" = [
                {
                  "name" = "RDS_DB_NAME"
                  "value" = "aws_db_instance.my_rds_instance.db_name"
                },
                {
                  "name" = "RDS_USERNAME"
                  "value" = "aws_db_instance.my_rds_instance.username"
                },
                {
                  "name" = "RDS_PASSWORD"
                  "value" = "aws_db_instance.my_rds_instance.password"
                },
                {
                  "name" = "RDS_HOSTNAME"
                  "value" = "aws_db_instance.my_rds_instance.address"
                },
                {
                  "name" = "RDS_PORT"
                  "value" = "var.rds_port"
                },
                {
                  "name" = "S3_BUCKET_NAME"
                  "value" = "aws_s3_bucket.ror-s3.bucket"
                },
                {
                  "name" = "S3_REGION_NAME"
                  "value" = "aws_s3_bucket.ror-s3.region"
                },
                {
                  "name" = "LB_ENDPOINT"
                  "value" = "kubernetes_manifest.service_ingress_nginx_ingress_nginx_controller.aws-load-balancer-url"
                },
              ]
              "image" = "076992707442.dkr.ecr.us-east-1.amazonaws.com/rails_app:latest"
              "imagePullPolicy" = "Always"
              "name" = "ror-application"
              "ports" = [
                {
                  "containerPort" = 3000
                  "name" = "http"
                  "protocol" = "TCP"
                },
              ]
            },
            {
              "image" = "076992707442.dkr.ecr.us-east-1.amazonaws.com/webserver:latest"
              "imagePullPolicy" = "Always"
              "name" = "web-application"
              "ports" = [
                {
                  "containerPort" = 8080
                  "name" = "http"
                  "protocol" = "TCP"
                },
              ]
            },
          ]
          "serviceAccountName" = "ror-sa"
        }
      }
    }
  }
}

resource "kubernetes_manifest" "ingress_ror_application" {
  manifest = {
    "apiVersion" = "networking.k8s.io/v1"
    "kind" = "Ingress"
    "metadata" = {
      "name" = "ror-application"
    }
    "spec" = {
      "ingressClassName" = "nginx"
      "rules" = [
        {
          "host" = "ror.application.com"
          "http" = {
            "paths" = [
              {
                "backend" = {
                  "service" = {
                    "name" = "web-app"
                    "port" = {
                      "number" = 8080
                    }
                  }
                }
                "path" = "/web-app"
                "pathType" = "Prefix"
              },
            ]
          }
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "serviceaccount_ror_sa" {
  manifest = {
    "apiVersion" = "v1"
    "kind" = "ServiceAccount"
    "metadata" = {
      "annotations" = {
        "eks.amazonaws.com/role-arn" = "arn:aws:iam::908261734603:role/ror-EKS-Role"
      }
      "name" = "ror-sa"
    }
  }
}

resource "kubernetes_manifest" "service_ror_service" {
  manifest = {
    "apiVersion" = "v1"
    "kind" = "Service"
    "metadata" = {
      "labels" = {
        "app" = "ror-service"
      }
      "name" = "ror-service"
    }
    "spec" = {
      "ports" = [
        {
          "name" = "http"
          "port" = 8080
          "protocol" = "TCP"
          "targetPort" = 8080
        },
      ]
      "selector" = {
        "app" = "ror-service"
      }
    }
  }
}

resource "aws_iam_policy" "ror-sa-role-policy" {
  name        = "ror-sa_policy"
  path        = "/"
  description = "Policy for Kubernetes Admin role that is assumed to manage the nodes"

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        "Sid"    = "rds",
        "Effect" = "Allow",
        "Action" = "rds:*"
        "Resource" = "*"
      },
      {
        "Sid"    = "s3",
        "Effect" = "Allow",
        "Action" = "s3:*"
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_role" "ror-sa-role" {
  name               = "ror-sa"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.ror-sa-assume-role-policy.json
}

resource "aws_iam_role_policy_attachment" "ror-sa-role-eks-perms" {
  role       = aws_iam_role.ror-sa-role.name
  policy_arn = aws_iam_policy.ror-sa-role-policy.arn
}





