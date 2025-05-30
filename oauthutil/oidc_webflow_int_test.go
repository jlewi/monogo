//go:build integration

package oauthutil

import (
	"fmt"
	"os"
	"testing"
)

func Test_NewWebFlowFromFlags(t *testing.T) {
	// Integration test useful for development/debugging
	// Google test
	//f := OIDCWebFlowFlags{
	//	Issuer:          "https://accounts.google.com",
	//	OAuthClientFile: "/Users/jlewi/secrets/roboweb-lewi-iap-oauth-client.json",
	//}

	tenantID := os.Getenv("TENANT_ID")

	if tenantID == "" {
		t.Fatalf("TENANT_ID not set")
	}

	// For Azure AD / Entra you can get all the openid information at
	// https://login.microsoftonline.com/${TENANT_ID}/v2.0/.well-known/openid-configuration

	f := OIDCWebFlowFlags{
		Issuer:          fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID),
		OAuthClientFile: "/Users/jlewi/secrets/azure-oauth-client.json",
	}

	flow, err := f.Flow()
	if err != nil {
		t.Fatalf("Failed to create flow; %v", err)
	}

	ts, err := flow.Run()

	if err != nil {
		t.Fatalf("Failed to run flow; %v", err)
	}

	fmt.Sprintf("Token Source: %T", ts)
	//idTs, ok := ts.(*IDTokenSource)
	//if !ok {
	//	t.Fatalf("Expected IDTokenSource got %T", ts)
	//}
	//
	idToken, err := ts.IDToken()
	if err != nil {
		t.Fatalf("Failed to get id token; %v", err)
	}
	fmt.Printf("ID Token: %v", idToken)
}
