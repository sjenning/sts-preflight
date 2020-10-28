**Update 10/27: This still has hardcoded values and it not suitable for general use yet. However it is useful for documenting the flow for setting up the required pre-install resources and configuration in AWS**
# sts-preflight
This is a tool for allowing Openshift to install using STS based credentials
## Download and Build
```bash
go get github.com/sjenning/sts-preflight
cd $GOPATH/src/github.com/sjenning/sts-preflight
go build .
```
## Usage
```
Usage:
  sts-preflight [command]

Available Commands:
  assume      A brief description of your command
  create      A brief description of your command
  destroy     A brief description of your command
  help        Help about any command
  token       A brief description of your command
```
### Create
```
./sts-preflight create
```
This command
* creates an RSA keypair
* create a JKWS document with the public part of the keypair
* creates an OIDC discovery document
* creates s3 bucket with the discovery and JKWS documents
* creates an OIDC provider in IAM whose issuer is the s3 bucket URL
* creates an installer Role with the OIDC provider as a Trusted Entity and attaches an Administrator policy

The role ARN is stored in `_output/role-arn`
### Token
```
./sts-create token
```
This command creates a JWT signed by the RSA private key and stores it in `_output/token`.  This token is validated by the OIDC provider, which contains the matching key ID (kid) in the JWKS.  The installer Role can then be assumed since the OIDC provider is a Trusted Entity for the Role.

After this step, one can `source scripts/set-role-creds.sh` to set `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`.  Then one can execute aws CLI commands allowing the CLI to do the `AssumeRoleWithWebIdentity` and use the STS issued credentials (cached until expiration).
