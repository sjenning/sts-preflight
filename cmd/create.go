package cmd

import (
	"os"

	"github.com/sjenning/sts-preflight/pkg/cmd/create"
	"github.com/sjenning/sts-preflight/pkg/jwks"
	"github.com/sjenning/sts-preflight/pkg/rsa"
	"github.com/sjenning/sts-preflight/pkg/s3endpoint"
	"github.com/spf13/cobra"
)

var (
	createConfig create.Config
	createState  create.State
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates STS infrastructure in AWS",
	Run: func(cmd *cobra.Command, args []string) {
		os.Mkdir("_output", 0700)

		createState.InfraName = createConfig.InfraName
		createState.Region = createConfig.Region
		rsa.New()
		jwks.New(&createState)
		s3endpoint.New(createConfig, &createState)
		createState.Write()
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	createCmd.PersistentFlags().StringVar(&createConfig.InfraName, "infra-name", "", "Name prefix for all created AWS resources")
	createCmd.MarkPersistentFlagRequired("infra-name")

	createCmd.PersistentFlags().StringVar(&createConfig.Region, "region", "", "AWS region were the s3 OIDC endpoint will be created")
	createCmd.MarkPersistentFlagRequired("region")
}
