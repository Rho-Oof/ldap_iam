#ldap proxy to aws iam

ensure aws credentials are available, possibly via IAM Role on ec2 instance

set AWS_REGION, GROUP_NAME, DOMAIN 
and optionally DEFAULT_GID, REQUIRE_UID, REQUIRE_GID, SECRET and PORT

## example for testing
>  export GROUP_NAME=MyUsers
>  export AWS_REGION=us-east-1
>  export DOMAIN=example.com
>  export SECRET=ldaprootaccountpasswordhere
>  export DEFAULT_GID=500
>  export REQUIRE_UID=$UID
>  export PORT=/var/run/ldap.sock

then run `node index.js` or `npm start`

## testing the service
the domain gets split into "DC=" based on the dots so example.com turns into 
dc=example,dc=com test.ldap.fred turns into dc=test,dc=ldap,dc=fred

```
ldapsearch -H ldapi://%2fvar%2frun%2fldap.sock/ -x -b ou=users,dc=example,dc=com objectclass=\*
```

connect to a unix socket as a specified user or group *or* 
connect with simple binding as cn=root with the secret as the password 

## NB port may be a file which should create a unix socket
when the using unix socket connection the process connecting will be validated 
against the REQUIRE_UID and REQUIRE_GID *at least* one must be set.  When using 
a TCP port if you have not set a SECRET one will be created for you and printed 
to STDOUT on each run
