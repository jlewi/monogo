// CLI is some command line interface.
package main

import (
	"fmt"
	"os"

	"github.com/jlewi/monogo/cli/commands"
	"github.com/jlewi/p22h/backend/pkg/logging"
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	var level string
	var jsonLog bool
	rootCmd := &cobra.Command{
		Short: "sugar for developers",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			_, err := logging.InitLogger(level, !jsonLog)
			if err != nil {
				panic(err)
			}
		},
	}

	rootCmd.PersistentFlags().StringVarP(&level, "level", "", "info", "The logging level.")
	rootCmd.PersistentFlags().BoolVarP(&jsonLog, "json-logs", "", false, "Enable json logging.")
	return rootCmd
}

func main() {
	rootCmd := newRootCmd()
	rootCmd.AddCommand(commands.NewKubectlContext())
	rootCmd.AddCommand(commands.NewJWTCommands())
	rootCmd.AddCommand(commands.NewIAPCommands())
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Command failed with error: %+v", err)
		os.Exit(1)
	}
}
