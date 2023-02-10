package iap

import (
	"context"

	"github.com/pkg/errors"
	"google.golang.org/api/idtoken"
)

const (
	// JWTHeader is the name of the header containing the JWT set by IAP
	// https://cloud.google.com/iap/docs/signed-headers-howto#securing_iap_headers
	JWTHeader  = "x-goog-iap-jwt-assertion"
	EmailClaim = "email"
)

// Verifier is a Verifier for IAP JWTs.
type Verifier struct {
	Aud string
}

// Verify verifies that the JWT header is properly signed by Google indicating the request went through IAP.
// https://cloud.google.com/iap/docs/signed-headers-howto#retrieving_the_user_identity
func (v *Verifier) Verify(iapJWT string) error {
	_, err := v.Email(iapJWT)
	return err
}

// Email verifies the JWT and if its valid returns the email
func (v *Verifier) Email(iapJWT string) (string, error) {
	payload, err := idtoken.Validate(context.Background(), iapJWT, v.Aud)
	if err != nil {
		return "", errors.Wrapf(err, "JWT is invalid")
	}

	emailClaim, ok := payload.Claims[EmailClaim]

	if !ok {
		return "", errors.Errorf("JWT is missing claim %v", EmailClaim)
	}

	email, ok := emailClaim.(string)
	if !ok {
		return "", errors.Errorf("Claim %v is not of type string", emailClaim)
	}

	return email, nil
}
