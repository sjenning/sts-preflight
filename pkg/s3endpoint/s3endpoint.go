package s3endpoint

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
)

var (
	discoveryURI      = ".well-known/openid-configuration"
	keysURI           = "keys.json"
	discoveryTemplate = `{
	"issuer": "%s",
	"jwks_uri": "%s/%s",
    "response_types_supported": [
        "id_token"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "claims_supported": [
        "aud",
        "exp",
        "sub",
        "iat",
        "iss",
        "sub"
    ]
}`
)

func New() {
	bucketName := "sjenning-oidc-provider"
	issuerURL := fmt.Sprintf("https://s3-us-west-1.amazonaws.com/%s", bucketName)
	roleName := "sjenning-installer-role"

	cfg := &awssdk.Config{
		Region: awssdk.String("us-west-1"),
	}

	s, err := session.NewSession(cfg)
	if err != nil {
		log.Fatal(err.Error())
	}

	s3Client := s3.New(s)
	iamClient := iam.New(s)

	_, err = s3Client.CreateBucket(&s3.CreateBucketInput{
		Bucket: awssdk.String(bucketName),
	})
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case s3.ErrCodeBucketAlreadyOwnedByYou:
				log.Print("Bucket ", bucketName, " already exists and is owned by us")
			default:
				log.Fatal(aerr.Error())
			}
		} else {
			log.Fatal(err.Error())
		}
	} else {
		log.Print("Bucket ", bucketName, " created")
	}

	discoveryJSON := fmt.Sprintf(discoveryTemplate, issuerURL, issuerURL, keysURI)
	_, err = s3Client.PutObject(&s3.PutObjectInput{
		ACL:    awssdk.String("public-read"),
		Body:   awssdk.ReadSeekCloser(strings.NewReader(discoveryJSON)),
		Bucket: awssdk.String(bucketName),
		Key:    awssdk.String(discoveryURI),
	})
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Print("OIDC discovery document at ", discoveryURI, " updated")

	f, err := os.Open("_output/keys.json")
	if err != nil {
		log.Fatal(err.Error())
	}

	_, err = s3Client.PutObject(&s3.PutObjectInput{
		ACL:    awssdk.String("public-read"),
		Body:   awssdk.ReadSeekCloser(f),
		Bucket: awssdk.String(bucketName),
		Key:    awssdk.String(keysURI),
	})
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Print("JWKS at ", keysURI, " updated")

	oidcProviderList, err := iamClient.ListOpenIDConnectProviders(&iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		log.Fatal(err.Error())
	}

	var providerARN string
	for _, provider := range oidcProviderList.OpenIDConnectProviderList {
		if strings.Contains(*provider.Arn, bucketName) {
			providerARN = *provider.Arn
			log.Print("Existing OIDC provider found ", providerARN)
			break
		}
	}

	if len(providerARN) == 0 {
		oidcOutput, err := iamClient.CreateOpenIDConnectProvider(&iam.CreateOpenIDConnectProviderInput{
			ClientIDList: []*string{
				awssdk.String("sts.amazonaws.com"),
			},
			ThumbprintList: []*string{
				awssdk.String("A9D53002E97E00E043244F3D170D6F4C414104FD"), // root CA thumbprint for s3 (DigiCert)
			},
			Url: awssdk.String(issuerURL),
		})
		if err != nil {
			log.Fatal(err.Error())
		}

		providerARN = *oidcOutput.OpenIDConnectProviderArn
		log.Print("OIDC provider created ", providerARN)
	}

	rolePolicyTemplate := `{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Principal": {
				"Federated": "%s"
			},
				"Action": "sts:AssumeRoleWithWebIdentity",
			"Condition": {
				"StringEquals": {
					"s3-us-west-1.amazonaws.com/sjenning-oidc-provider:aud": "sts.amazonaws.com"
				}
			}
		}
	]
}`

	roleList, err := iamClient.ListRoles(&iam.ListRolesInput{MaxItems: awssdk.Int64(500)})
	if err != nil {
		log.Fatal(err.Error())
	}

	var roleARN string
	for _, role := range roleList.Roles {
		if *role.RoleName == roleName {
			roleARN = *role.Arn
			log.Print("Existing Role found ", roleARN)
			break
		}
	}

	if len(roleARN) == 0 {
		roleOutput, err := iamClient.CreateRole(&iam.CreateRoleInput{
			RoleName:                 awssdk.String(roleName),
			AssumeRolePolicyDocument: awssdk.String(fmt.Sprintf(rolePolicyTemplate, providerARN)),
		})
		if err != nil {
			log.Fatal(err.Error())
		}

		roleARN = *roleOutput.Role.Arn
		log.Print("Role created ", roleARN)
	}

	_, err = iamClient.AttachRolePolicy(&iam.AttachRolePolicyInput{
		PolicyArn: awssdk.String("arn:aws:iam::aws:policy/AdministratorAccess"),
		RoleName:  awssdk.String(roleName),
	})
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Print("AdministratorAccess attached to Role ", roleName)
}
