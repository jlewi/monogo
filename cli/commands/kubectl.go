package commands

import (
	"fmt"
	"os"

	"github.com/jlewi/monogo/helpers"

	"github.com/go-logr/zapr"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubectl/pkg/cmd/config"
)

// NewKubectlContext creates a new kubectl context
func NewKubectlContext() *cobra.Command {
	var name string
	var namespace string
	cmd := &cobra.Command{
		Use:   "create-context",
		Short: "Creates a kubectl context with the specified name and namespace",
		Run: func(cmd *cobra.Command, args []string) {
			log := zapr.NewLogger(zap.L())
			err := func() error {
				log.Info("Getting current context")
				options := &config.CurrentContextOptions{ConfigAccess: clientcmd.NewDefaultPathOptions()}
				startingConfig, err := options.ConfigAccess.GetStartingConfig()
				if err != nil {
					return errors.Wrapf(err, "Failed to GetStartingConfig")
				}
				if startingConfig.CurrentContext == "" {
					err = fmt.Errorf("current-context is not set")
					return err
				}

				log.Info("starting with context", "context", startingConfig.CurrentContext)

				// Start with the current context
				startingStanza, exists := startingConfig.Contexts[startingConfig.CurrentContext]
				if !exists {
					return errors.Errorf("Current context %v doesn't exist", startingConfig.CurrentContext)
				}

				if name == "" {
					name = namespace
					log.Info("No name provided defaulting to namespace", "name", name)
				}

				if _, ok := startingConfig.Contexts[name]; ok {
					return errors.Errorf("Context with name %v already exists", name)
				}

				// Copy the current context and modify it
				modified := *startingStanza

				modified.Namespace = namespace

				startingConfig.Contexts[name] = &modified
				if err := clientcmd.ModifyConfig(options.ConfigAccess, *startingConfig, true); err != nil {
					return errors.Wrapf(err, "Failed to persist the new context")
				}
				fmt.Fprintf(os.Stdout, "Created context %v; namespace=%v cluster=%v", name, namespace, modified.Cluster)
				return nil
			}()
			if err != nil {
				fmt.Printf("Error: %+v", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "The name for the context if not specified defaults to namespace")
	cmd.Flags().StringVarP(&namespace, "namespace", "", "", "Namespace")
	helpers.IgnoreError(cmd.MarkFlagRequired("namespace"))
	return cmd
}
