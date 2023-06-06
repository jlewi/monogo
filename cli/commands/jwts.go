package commands

import (
	"context"
	"fmt"
	"os"

	firebase "firebase.google.com/go/v4"
	"google.golang.org/api/option"

	"github.com/MicahParks/keyfunc"
	"github.com/go-logr/zapr"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jlewi/monogo/helpers"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// NewJWTCommands creates new commands for working with JWTs
func NewJWTCommands() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwts",
		Short: "Commands for working with JWTS",
	}

	cmd.AddCommand(NewParseJWTCommand())
	cmd.AddCommand(NewFirebaseCommands())
	//cmd.AddCommand(NewCreateJWTCommand())
	return cmd
}

// NewParseJWTCommand creates a command to parse a JWT
func NewParseJWTCommand() *cobra.Command {
	var jwksURL string
	cmd := &cobra.Command{
		Use:   "parse [JWT]",
		Args:  cobra.ExactArgs(1),
		Short: "Parse validates the signature on a JWT encoded as a base64 string and pretty prints.",
		Long: `Parse and validates a JWT. 
JWTs corresponding to Google ID Tokens can be obtained using gcloud e.g.

JWT=$(gcloud auth print-identity-token)
devCli jwts parse ${JWT}

This command is useful for inspecting the JWT to see claims and other information.
`,
		Run: func(cmd *cobra.Command, args []string) {
			log := zapr.NewLogger(zap.L())
			err := func() error {
				log.Info("Parsing JWT")
				jot := args[0]

				// Google Open ID connect signer
				// comes from the discover doc
				if jwksURL != "" {
					jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{}) // See recommended options in the examples directory.
					if err != nil {
						return errors.Wrapf(err, "Failed to get the JWKS from the given URL.")
					}
					token, err := jwt.Parse(jot, jwks.Keyfunc)

					if err != nil {
						return errors.Wrapf(err, "Failed to parse JWT")
					}

					fmt.Fprintf(os.Stdout, "Token:\n%v\n", helpers.PrettyString(token))
				} else {
					fmt.Fprintf(os.Stdout, "No JWKS URL specified; not validating signature")
					claims := jwt.MapClaims{}
					p := jwt.NewParser()
					token, _, err := p.ParseUnverified(jot, claims)
					if err != nil {
						return errors.Wrapf(err, "Failed to ParseUnverified jot")
					}
					fmt.Fprintf(os.Stdout, "Token:\n%v\n", helpers.PrettyString(token))
					fmt.Fprintf(os.Stdout, "Claims:\n%v\n", helpers.PrettyString(claims))
					return nil
				}

				return nil
			}()
			if err != nil {
				fmt.Printf("Error: %+v", err)
				os.Exit(1)
			}
		},
	}

	// https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com
	// Is JWKs for firebase
	cmd.Flags().StringVarP(&jwksURL, "jwks", "", "https://www.googleapis.com/oauth2/v3/certs", "The URL of the JWKs key used to validate the signature. Default is for Google ID tokens. Set it to the empty string to do no validation")
	return cmd
}

func NewFirebaseCommands() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firebase",
		Short: "Commands for working with firebase JWTS",
	}

	cmd.AddCommand(NewCreateFirebaseJWTCommand())
	cmd.AddCommand(NewParseFirebaseJWTCommand())
	return cmd
}

// NewCreateFirebaseJWTCommand creates a command to parse a JWT
func NewCreateFirebaseJWTCommand() *cobra.Command {
	var project string
	var uid string
	var email string
	var adminSA string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a firebase JWT",
		Run: func(cmd *cobra.Command, args []string) {
			log := zapr.NewLogger(zap.L())
			err := func() error {
				log.Info("Creating JWT")
				config := &firebase.Config{
					ProjectID: project,
				}
				opt := option.WithCredentialsFile(adminSA)
				app, err := firebase.NewApp(context.Background(), config, opt)

				if err != nil {
					return errors.Wrapf(err, "error initializing app")
				}

				ctx := context.Background()
				client, err := app.Auth(ctx)
				if err != nil {
					return errors.Wrapf(err, "error getting Auth client")
				}
				claims := map[string]interface{}{
					"email": email,
				}
				token, err := client.CustomTokenWithClaims(context.Background(), uid, claims)

				if err != nil {
					return errors.Wrapf(err, "error minting custom token")
				}

				fmt.Fprintf(os.Stdout, "Token:\n%v\n", helpers.PrettyString(token))
				return nil
			}()
			if err != nil {
				fmt.Printf("Error: %+v", err)
				os.Exit(1)
			}
		},
	}

	// https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com
	// Is JWKs for firebase
	cmd.Flags().StringVarP(&project, "project", "", "", "The firebase project to make the JWT for")
	cmd.Flags().StringVarP(&uid, "uid", "", "", "The user id to make the JWT for")
	cmd.Flags().StringVarP(&email, "email", "", "", "The email make the JWT for")
	cmd.Flags().StringVarP(&adminSA, "secret", "", "", "JSON file containg the secret for the admin service account. Download this from the GCP service accounts page")
	helpers.IgnoreError(cmd.MarkFlagRequired("project"))
	helpers.IgnoreError(cmd.MarkFlagRequired("secret"))
	return cmd
}

// NewParseFirebaseJWTCommand creates a command to parse a JWT
func NewParseFirebaseJWTCommand() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "parse [JWT]",
		Args:  cobra.ExactArgs(1),
		Short: "Parse validates the signature on a JWT encoded as a base64 string and pretty prints it.",
		Long: `Parse and validates a firebase IDToken.

Firebase IDTokens are not the same as firebase custom tokens.

This command is useful for inspecting the JWT to see claims and other information.
`,
		Run: func(cmd *cobra.Command, args []string) {
			log := zapr.NewLogger(zap.L())
			err := func() error {
				log.Info("Parsing JWT")
				jot := args[0]
				config := &firebase.Config{
					ProjectID: project,
				}
				app, err := firebase.NewApp(context.Background(), config)

				if err != nil {
					return errors.Wrapf(err, "error initializing app")
				}

				ctx := context.Background()
				client, err := app.Auth(ctx)
				if err != nil {
					return errors.Wrapf(err, "error getting Auth client")
				}
				token, err := client.VerifyIDToken(ctx, jot)

				if err != nil {
					return errors.Wrapf(err, "error validating token")
				}

				fmt.Fprintf(os.Stdout, "Token:\n%v\n", helpers.PrettyString(token))
				return nil
			}()
			if err != nil {
				fmt.Printf("Error: %+v", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVarP(&project, "project", "", "", "The firebase project to make the JWT for")
	helpers.IgnoreError(cmd.MarkFlagRequired("project"))
	return cmd
}
