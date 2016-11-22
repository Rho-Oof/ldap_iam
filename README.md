#ldap proxy to aws iam

ensure aws credentials are available, possibly via IAM Role to ec2 instance

set GROUP_NAME,DOMAIN,DOMAIN and optionally DEFAULT_GID
## example
>  export GROUP_NAME=MyUsers
>  export AWS_REGION=us-east-1
>  export DOMAIN=example.com

then run node index.js or npm start
