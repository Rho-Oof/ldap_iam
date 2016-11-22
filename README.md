#ldap proxy to aws iam

ensure aws credentials are available, possibly via IAM Role to ec2 instance

set GROUP_NAME,DOMAIN,DOMAIN and optionally DEFAULT_GID, DEFAULT_UID, SECRET and PORT
## example
>  export GROUP_NAME=MyUsers
>  export AWS_REGION=us-east-1
>  export DOMAIN=example.com
>  export SECRET=ldaprootaccountpasswordhere

then run node index.js or npm start

connect with simple binding as cn=root with the secret as the password

## NB port may be a file which should create a unix socket
when the using unix socket connection the process connecting will be validated against
the DEFAULT_GID and DEFAULT_UID *at least* one must be set
