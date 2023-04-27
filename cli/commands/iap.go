package commands

import (
	"context"
	"fmt"
	"os"

	compute "cloud.google.com/go/compute/apiv1"
	iap "cloud.google.com/go/iap/apiv1"
	"github.com/go-logr/zapr"
	"github.com/jlewi/monogo/api/v1alpha1"
	"github.com/jlewi/monogo/helpers"
	iapLib "github.com/jlewi/monogo/iap"
	"github.com/jlewi/monogo/k8s"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/oauth2/google"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

// NewIAPCommands creates new commands for working with IAP
func NewIAPCommands() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iap",
		Short: "Commands for working with Google Cloud IAP",
	}

	cmd.AddCommand(NewGetIAMPolicy())
	cmd.AddCommand(NewSetIAMPolicy())
	cmd.AddCommand(CreateOAuthClientSecret())
	return cmd
}

// NewGetIAMPolicy gets the IAM policy
func NewGetIAMPolicy() *cobra.Command {
	var project string
	var backend string
	var namespace string
	var service string
	var ingress string
	k8sFlags := &k8s.K8SClientFlags{}

	cmd := &cobra.Command{
		Use:   "get-iam-policy",
		Short: "Get the IAM policy for a resource.",
		Run: func(cmd *cobra.Command, args []string) {
			log := zapr.NewLogger(zap.L())
			err := func() error {
				log.Info("Get IAM Policy JWT")
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

	k8sFlags.AddFlags(cmd)
	cmd.Flags().StringVarP(&project, "project", "", "", "The project ID or number that owns the backend resource")
	cmd.Flags().StringVarP(&service, "service", "", "", "The K8s service to get the IAP policy for.")
	cmd.Flags().StringVarP(&namespace, "namespace", "", "", "The K8s namespace containing the ingress and service.")
	cmd.Flags().StringVarP(&ingress, "ingress", "", "", "The K8s ingress to get the policy for.")
	cmd.Flags().StringVarP(&backend, "backend", "", "", "The backend ID or number. This will be stored in the ingress.kubernetes.io/backends annotation.")
	return cmd
}

// NewSetIAMPolicy sets the IAM policy
// We should support K8s apply -f semantics and use the kyaml libraries to find and apply all resources.
func NewSetIAMPolicy() *cobra.Command {
	var policyFile string
	k8sFlags := &k8s.K8SClientFlags{}
	cmd := &cobra.Command{
		Use:   "set-iam-policy",
		Short: "Sets the IAM IAP policy for a resource. This completely overrides the policy with the specified one",
		Run: func(cmd *cobra.Command, args []string) {
			log := zapr.NewLogger(zap.L())
			err := func() error {
				f, err := os.Open(policyFile)
				if err != nil {
					return errors.Wrapf(err, "Failed to read policy file: %v", policyFile)
				}
				defer f.Close()

				d := yaml.NewDecoder(f)

				policy := &v1alpha1.IAPAppPolicy{}

				if err := d.Decode(policy); err != nil {
					return errors.Wrapf(err, "Failed to read IAPAppPolicy from %v", policyFile)
				}
				log.Info("Set IAM Policy JWT")
				ctx := context.Background()
				c, err := iap.NewIdentityAwareProxyAdminClient(ctx)
				if err != nil {
					return errors.Wrapf(err, "Failed to create IAP Admin client")
				}
				defer helpers.DeferIgnoreError(c.Close)

				bSvc, err := compute.NewBackendServicesRESTClient(context.Background())
				defer helpers.DeferIgnoreError(bSvc.Close)

				if err != nil {
					return errors.Wrapf(err, "Failed to create backend service client")
				}

				if isValid, msg := policy.IsValid(); !isValid {
					return errors.Errorf("policy is invalid; %v", msg)
				}
				external := policy.Spec.ResourceRef.External

				if policy.Spec.ResourceRef.ServiceRef != nil {
					// Determine the backend id from the K8s service.
					client, err := k8sFlags.NewClient()
					if err != nil {
						return err
					}

					namespace := policy.Spec.ResourceRef.ServiceRef.Namespace
					svcName := policy.Spec.ResourceRef.ServiceRef.Service
					project := policy.Spec.ResourceRef.ServiceRef.Project

					ingressName := policy.Spec.ResourceRef.ServiceRef.Ingress
					var backend string
					if ingressName == "" {
						negs, err := iapLib.GetGCPBackendFromService(client, bSvc, project, namespace, svcName)
						if err != nil {
							return err
						}

						if len(negs) == 0 {
							return errors.Errorf("No NEG found for service %v/%v", namespace, svcName)
						}

						if len(negs) > 1 {
							// TODO(jeremy): Service could have multiple ports. Should we specify the port in the
							// policy on which to attach the IAP policy to
							return errors.Errorf("Multiple NEG found for service %v/%v; code needs to be updated to handle this", namespace, svcName)
						}

						for _, b := range negs {
							backend = b
						}
					} else {
						// TODO(jeremy): Can we deprecate this code path? I think the other approach works regardless
						// of whether an ingress or gateway is used
						backend, err = iapLib.GetGCPBackend(client, namespace, svcName, ingressName)
						if err != nil {
							return err
						}
					}

					external = iapLib.BackendIAPName(policy.Spec.ResourceRef.ServiceRef.Project, backend)
				}

				log.Info("Set IAP IAM Policy", "resource", external)
				req := &iampb.SetIamPolicyRequest{
					Resource: external,
					Policy: &iampb.Policy{
						Bindings: make([]*iampb.Binding, 0, len(policy.Spec.Bindings)),
					},
				}

				for _, b := range policy.Spec.Bindings {
					req.Policy.Bindings = append(req.Policy.Bindings, &iampb.Binding{
						Role:    b.Role,
						Members: b.Members,
					})
				}

				resp, err := c.SetIamPolicy(ctx, req)
				if err != nil {
					return errors.Wrapf(err, "Failed to SetIamPolicy")
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

	k8sFlags.AddFlags(cmd)
	cmd.Flags().StringVarP(&policyFile, "file", "f", "", "The YAML file containing the policy to apply")
	helpers.IgnoreError(cmd.MarkFlagRequired("file"))
	return cmd
}

// CreateOAuthClientSecret creates a secret in the K8s cluster containing the specified OAuth client
// TODO(jeremy): We should just adopt k8s apply semantics and have a YAML declaration that applies the secrets.
func CreateOAuthClientSecret() *cobra.Command {
	var namespace string
	var k8sContext string
	var name string
	var file string
	k8sFlags := &k8s.K8SClientFlags{}

	cmd := &cobra.Command{
		Use:   "create-secret",
		Short: "Create a secret from the oauth client file.",
		Run: func(cmd *cobra.Command, args []string) {
			log := zapr.NewLogger(zap.L())
			err := func() error {
				log.Info("Create IAP OAuth client secret")
				b, err := os.ReadFile(file)
				if err != nil {
					return errors.Wrapf(err, "Failed to read file %v", file)
				}

				config, err := google.ConfigFromJSON(b)
				if err != nil {
					return errors.Wrapf(err, "Failed to read OAuth2 config from file %v", file)
				}

				client, err := k8sFlags.NewClient()

				if err != nil {
					return err
				}

				secret := &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
					StringData: map[string]string{
						"client_id":     config.ClientID,
						"client_secret": config.ClientSecret,
					},
					Type: "Opaque",
				}
				_, err = client.CoreV1().Secrets(namespace).Update(context.Background(), secret, metav1.UpdateOptions{})
				// Check if its a kubernetes not found error
				if err != nil {
					if !kerrors.IsNotFound(err) {
						return errors.Wrapf(err, "Failed to create secret %v.%v", namespace, name)
					}
					_, err = client.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
					if err != nil {
						return errors.Wrapf(err, "Failed to create secret %v.%v", namespace, name)
					}
				}
				fmt.Printf("Updated secret %v.%v", namespace, name)
				return nil
			}()
			if err != nil {
				fmt.Printf("Error: %+v", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&name, "name", "", "", "The name for the key")
	cmd.Flags().StringVarP(&namespace, "namespace", "", "", "The namespace for the key")
	cmd.Flags().StringVarP(&k8sContext, "context", "", "", "The context")
	cmd.Flags().StringVarP(&file, "file", "", "", "file containing the OAuth client id")
	k8sFlags.AddFlags(cmd)
	return cmd
}
