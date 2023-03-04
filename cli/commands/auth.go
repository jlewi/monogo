package commands

import (
	iap "cloud.google.com/go/iap/apiv1"
	"context"
	"fmt"
	"github.com/go-logr/zapr"
	"github.com/jlewi/monogo/helpers"
	iapLib "github.com/jlewi/monogo/iap"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"os"
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
				ctx := context.Background()
				c, err := iap.NewIdentityAwareProxyAdminClient(ctx)
				if err != nil {
					return errors.Wrapf(err, "Failed to create IAP Admin client")
				}
				defer c.Close()

				if backend == "" {
					// Determine the backend id from the K8s service.
					client, err := k8sFlags.NewClient()
					if err != nil {
						return err
					}

					backend, err = iapLib.GetGCPBackend(client, namespace, service, ingress)
					if err != nil {
						return err
					}
				} else {
					if namespace != "" && service != "" && ingress != "" {
						return errors.Errorf("If --backend is supplied --namespace, --service, and --ingress should not be set")
					}
				}

				resource := iapLib.BackendIAPName(project, backend)
				log.Info("Get Resource IAP IAM Policy", "resource", resource)
				req := &iampb.GetIamPolicyRequest{
					Resource: resource,
				}
				resp, err := c.GetIamPolicy(ctx, req)
				if err != nil {
					return errors.Wrapf(err, "Failed to GetIamPolicy")
				}
				fmt.Fprintf(os.Stdout, "Policy:\n%v", helpers.PrettyString(resp))
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
