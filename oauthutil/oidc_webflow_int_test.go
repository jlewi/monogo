//go:build integration

package oauthutil

import (
	"fmt"
	"testing"
)

func Test_NewWebFlowFromFlags(t *testing.T) {
	// Integration test useful for development/debugging
	f := OIDCWebFlowFlags{
		Issuer:          "https://accounts.google.com",
		OAuthClientFile: "/Users/jlewi/secrets/roboweb-lewi-iap-oauth-client.json",
	}

	flow, err := f.Flow()
	if err != nil {
		t.Fatalf("Failed to create flow; %v", err)
	}

	ts, err := flow.Run()

	if err != nil {
		t.Fatalf("Failed to run flow; %v", err)
	}

	idTs, ok := ts.(*IDTokenSource)
	if !ok {
		t.Fatalf("Expected IDTokenSource got %T", ts)
	}

	idToken, err := idTs.IDToken()
	if err != nil {
		t.Fatalf("Failed to get id token; %v", err)
	}
	fmt.Printf("ID Token: %v", idToken)
}
