package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version information
	version = "dev"
	arch    = "dev"

	// Flags
	policyPath string
)

var (
	rootCmd = &cobra.Command{
		SilenceUsage: true,
		Short:        "Validate cloud resource tags against a defined policy.",
		Long: `Tag Patrol scans cloud resources (initially AWS via Resource Explorer) and validates
their tags based on rules defined in a YAML policy file.

Policies can enforce mandatory tags, validate tag values (type, regex, allowed list,
numeric range), and apply conditional rules (e.g., if 'env=prod', then 'owner' must exist).
The tool reports resources that are non-compliant with the defined tagging standards,
helping maintain governance and consistency.`,
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("TagPatrol version %v %v\n", version, arch)
		},
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(awsCmd)
	rootCmd.AddCommand(versionCmd)

	rootCmd.PersistentFlags().StringVar(&policyPath, "policy", "", "The path to the policy file (YAML format).")
	rootCmd.MarkPersistentFlagRequired("policy")
}
