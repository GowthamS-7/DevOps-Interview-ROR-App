Steps:

Infrastructure:

1. docker/nginx/default.conf ---> Before building the image chagne the upstrem and server name from rails_app --> rails-app (since _ will not work in EKS deployments)

2. using "docker-compose build"  --> Build the both Rails app and webserver

3. Move to path--> /infrastructure --> Execute terraform commands, It will creata a s3 bucket and dynamo db to store the terraform state details

4. Move to path--> /infrstructure/EKS/  ---> Execute the terraform commmands, It will create the following resources:
               VPC,ECR, S3 bucket, EKS cluster,Postgres DB, AWS Load balancer controller


5. After ECR repostiory got provisioned, push the docker images which we build to the repo.             

               With this we are done with our Infrastructure provisioning


EKS Deployment:

Prerequisites:
                1.AWS CLI
                2.Kubectl CLI

     for more details: https://docs.qovery.com/guides/tutorial/how-to-connect-to-your-eks-cluster-with-kubectl/           

1.Using AWS CLI configure your AWS user/role in the machine with neccessary permisions

2.We need to update the configuraion file for EKS

 run--> aws eks update-kubeconfig --region us-east-1 --name mvw-eks-cluster
  
         i.e. replace the <mvw-eks-cluster> with respective eks cluster name and region

3.Once we are connected with the cluster, we can deploy our applications,
 
 Move to path ----> /infrastructure/Deployment_manifests

 Run the following commands:
 
 kubectl apply -f service.yml

 kubectl apply -f web-deployment.yml

 kubectl apply -f web-service.yml

 kubectl apply -f ingress.yml

 Once you ran the above commands, your web server will be deployed and ALB will be created and attached with the ingress.

update the "deployment.yml" with the right Environment variables like DB details, S3 details and LB endpoint, 

After updating the values, run the below command,

kubectl apply -f deployment.yml

By this,we deployed our rails app, Then use the ALB endpoint in the browser to test the application.


