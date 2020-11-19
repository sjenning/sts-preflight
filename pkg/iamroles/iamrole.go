package iamroles

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"

	"k8s.io/apimachinery/pkg/util/yaml"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"

	"github.com/sjenning/sts-preflight/pkg/cmd/create"
)

const (
	manifestsDir = "_manifests"
)

func Create(createConfig create.Config, oidcProviderARN, issuerURL string) {
	if createConfig.CredentialsRequestsFile == "" {
		return
	}

	crFile, err := os.Open(createConfig.CredentialsRequestsFile)
	if err != nil {
		log.Fatalf("failed to open credentials request file: %s\n", err)
	}

	if err := os.MkdirAll(manifestsDir, 0700); err != nil {
		log.Fatalf("unable to create directory to store credentials Secrets: %s", err)
	}

	decoder := yaml.NewYAMLOrJSONDecoder(crFile, 4096)
	for {
		cr := &credreqv1.CredentialsRequest{}
		if err := decoder.Decode(cr); err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("Failed to decode CredentialsRequest: %s", err)
		}

		processCredentialsRequest(cr, createConfig.InfraName, oidcProviderARN, issuerURL)
	}
}

func processCredentialsRequest(cr *credreqv1.CredentialsRequest, infraName, oidcProviderARN, issuerURL string) {
	codec, err := credreqv1.NewCodec()
	if err != nil {
		fmt.Printf("Failed to create credReq codec: %s\n", err)
		return
	}

	awsProviderSpec := credreqv1.AWSProviderSpec{}
	if err := codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &awsProviderSpec); err != nil {
		log.Fatalf("failed to decode the provider spec: %s\n", err)
		return
	}

	if awsProviderSpec.Kind != "AWSProviderSpec" {
		fmt.Printf("CredentialsRequest %s/%s is not of type AWS\n", cr.Namespace, cr.Name)
		return
	}

	// infraName-targetNamespace-targetSecretName
	roleName := fmt.Sprintf("%s-%s-%s", infraName, cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	roleARN := createRole(roleName, awsProviderSpec.StatementEntries, fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name), oidcProviderARN, issuerURL)

	writeSecret(cr, roleARN)
}

func createRole(roleName string, statementEntries []credreqv1.StatementEntry, namespacedName, oidcProviderARN, issuerURL string) string {

	var shortenedRoleName string
	if len(roleName) > 64 {
		shortenedRoleName = roleName[0:64]
	} else {
		shortenedRoleName = roleName
	}

	sess := session.Must(session.NewSession())
	iamClient := iam.New(sess)

	var role *iam.Role
	outRole, err := iamClient.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(shortenedRoleName),
	})

	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:

				// TODO: add conditions so that only the right ServiceAccount(s) can assume the role.
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
									"%s:aud": "openshift"
								}
							}
						}
					]
				}`

				roleOutput, err := iamClient.CreateRole(&iam.CreateRoleInput{
					RoleName:                 aws.String(shortenedRoleName),
					Description:              aws.String(fmt.Sprintf("OpenShift role for %s", namespacedName)),
					AssumeRolePolicyDocument: aws.String(fmt.Sprintf(rolePolicyTemplate, oidcProviderARN, issuerURL)),
				})
				if err != nil {
					log.Fatalf("Failed to create role: %s", err)
				}

				role = roleOutput.Role
				log.Printf("Role %s created", *role.Arn)

			default:
				log.Fatal(err.Error())
			}

		}
	} else {
		role = outRole.Role
		log.Printf("Existing role %s found", *role.Arn)
	}

	policy := createRolePolicy(statementEntries)
	_, err = iamClient.PutRolePolicy(&iam.PutRolePolicyInput{
		PolicyName:     aws.String(shortenedRoleName),
		RoleName:       role.RoleName,
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		log.Fatalf("Failed to put role policy: %s", err)
	}

	return *role.Arn
}

// StatementEntry is a simple type used to serialize to AWS' PolicyDocument format.
type StatementEntry struct {
	Effect   string
	Action   []string
	Resource string
	// Must "omitempty" otherwise we send unacceptable JSON to the AWS API when no
	// condition is defined.
	Condition credreqv1.IAMPolicyCondition `json:",omitempty"`
}

// PolicyDocument is a simple type used to serialize to AWS' PolicyDocument format.
type PolicyDocument struct {
	Version   string
	Statement []StatementEntry
}

func createRolePolicy(statements []credreqv1.StatementEntry) string {
	policyDocument := PolicyDocument{
		Version:   "2012-10-17",
		Statement: []StatementEntry{},
	}

	for _, entry := range statements {
		policyDocument.Statement = append(policyDocument.Statement,
			StatementEntry{
				Effect:    entry.Effect,
				Action:    entry.Action,
				Resource:  entry.Resource,
				Condition: entry.PolicyCondition,
			})
	}

	b, err := json.Marshal(&policyDocument)
	if err != nil {
		log.Fatalf("Failed to marshal the policy to JSON: %s", err)
	}

	return string(b)
}

func writeSecret(cr *credreqv1.CredentialsRequest, roleARN string) {
	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	fileData := fmt.Sprintf(`apiVersion: v1
stringData:
  credentials: |-
    [default]
    role_arn = %s
    web_identity_token_file = /var/run/secrets/openshift/serviceaccount/token
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
`, roleARN, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		log.Fatalf("Failed to save Secret file: %s", err)
	}

	log.Printf("Saved credentials configuration to: %s", filePath)
}
