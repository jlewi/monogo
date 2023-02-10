package commands

import (
	"fmt"
	"os"

	"github.com/MicahParks/keyfunc"
	"github.com/go-logr/zapr"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/jlewi/monogo/helpers"
	"go.uber.org/zap"
)

// NewJWTCommands creates new commands for working with JWTs
func NewJWTCommands() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwts",
		Short: "Commands for working with JWTS",
	}

	cmd.AddCommand(NewParseJWTCommand())
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

JWT=$(gcloud gcloud auth print-identity-token)
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

	cmd.Flags().StringVarP(&jwksURL, "jwks", "", "https://www.googleapis.com/oauth2/v3/certs", "The URL of the JWKs key used to validate the signature. Default is for Google ID tokens. Set it to the empty string to do no validation")
	return cmd
}
