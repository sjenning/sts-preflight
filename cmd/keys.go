package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/sjenning/sts-preflight/pkg/cmd/keys"
)

var (
	keysConfig keys.Config
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Create/generate new ServiceAccount keys",
	Run: func(cmd *cobra.Command, args []string) {
		runKeys()
	},
}

func init() {
	rootCmd.AddCommand(keysCmd)

	keysCmd.PersistentFlags().StringVar(&keysConfig.ExistingKeysJSONFile, "merge-with-keys-json", "", "Path to preexisting OIDC keys.json")
	keysCmd.PersistentFlags().StringVar(&keysConfig.TargetDir, "dir", "", "Directory to save generated keys/files")
	keysCmd.MarkPersistentFlagRequired("dir")
}

func runKeys() {

	if _, err := os.Stat(keysConfig.TargetDir); err == nil {
		log.Fatalf("Target dir %s already exists", keysConfig.TargetDir)
	}

	if err := os.Mkdir(keysConfig.TargetDir, 0700); err != nil {
		log.Fatalf("Failed to create directory: %s", err)
	}

	keys.GenerateKeys(keysConfig)

	keys.GenerateSecret(keysConfig)

	log.Printf("New keys.json saved to %s/keys.json", keysConfig.TargetDir)
	log.Printf("Secret with new ServiceAccount signing keys saved to %s/next-bound-service-account-signing-key", keysConfig.TargetDir)
}
