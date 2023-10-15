This terraform code provisions the asked infrastucture into AWS environment. 

Main.tf - file consists the creation of VPC, EKS cluster, IAM roles, ECR repository, RDS Postgres instance, S3 bucket

And have the deployment manifest scripts for EKS deployment of Web and Rails application container.

The EKS cluster consists of advanced Network load balancer with a Nginx ingress controller to load balance and scale the enviornment.
