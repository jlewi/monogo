package commands

import (
	"fmt"
	"os"

	"github.com/go-logr/zapr"
	"github.com/jlewi/monogo/oauthutil"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// NewAuth creates new commands for working with authorization
func NewAuthCommands() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Commands for working with various forms of authentication",
	}

	cmd.AddCommand(NewLoginCommand())
	return cmd
}

// NewLoginCommand obtains a credential for the specified service.
func NewLoginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to the specified service.",
		Run: func(cmd *cobra.Command, args []string) {
			log := zapr.NewLogger(zap.L())
			err := func() error {
				log.Info("Login")

				flow, err := oauthutil.NewFirebaseFlowServer()
				if err != nil {
					return err
				}

				flow.Run()
				return nil
			}()
			if err != nil {
				fmt.Printf("Error: %+v", err)
				os.Exit(1)
			}
		},
	}

	//k8sFlags.AddFlags(cmd)
	//cmd.Flags().StringVarP(&project, "project", "", "", "The project ID or number that owns the backend resource")
	//cmd.Flags().StringVarP(&service, "service", "", "", "The K8s service to get the IAP policy for.")
	//cmd.Flags().StringVarP(&namespace, "namespace", "", "", "The K8s namespace containing the ingress and service.")
	//cmd.Flags().StringVarP(&ingress, "ingress", "", "", "The K8s ingress to get the policy for.")
	//cmd.Flags().StringVarP(&backend, "backend", "", "", "The backend ID or number. This will be stored in the ingress.kubernetes.io/backends annotation.")
	return cmd
}
