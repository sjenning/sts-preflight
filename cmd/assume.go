package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/sjenning/sts-preflight/pkg/cmd/create"
	"github.com/spf13/cobra"
)

var assumeDir string

// assumeCmd represents the assume command
var assumeCmd = &cobra.Command{
	Use:   "assume",
	Short: "Get STS credentials using an OIDC token",
	Run: func(cmd *cobra.Command, args []string) {
		execute()
	},
}

func init() {
	rootCmd.AddCommand(assumeCmd)

	rootCmd.PersistentFlags().StringVar(&assumeDir, "dir", "_output", "Directory containing generated token")
	// assumeCmd.PersistentFlags().String("foo", "", "A help for foo")
}

func execute() {
	var state create.State
	state.Read()

	tokenFilePath := filepath.Join(assumeDir, "token")
	tokenBytes, err := ioutil.ReadFile(tokenFilePath)
	if err != nil {
		log.Fatal(err)
	}

	cfg := &awssdk.Config{
		Region: awssdk.String(state.Region),
	}

	s, err := session.NewSession(cfg)
	if err != nil {
		log.Fatal(err.Error())
	}

	stsClient := sts.New(s)

	output, err := stsClient.AssumeRoleWithWebIdentity(&sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          awssdk.String(state.RoleARN),
		WebIdentityToken: awssdk.String(string(tokenBytes)),
		RoleSessionName:  awssdk.String(fmt.Sprintf("%s-installer-session", state.InfraName)),
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("Run these commands to use the STS credentials")
	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", *output.Credentials.AccessKeyId)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", *output.Credentials.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=%s\n", *output.Credentials.SessionToken)
}
