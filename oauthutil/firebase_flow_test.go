package oauthutil

import (
	"github.com/jlewi/p22h/backend/pkg/logging"
	"os"
	"testing"
)

func Test_FirebaseFlowE2E(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("Skipping test because it requires user interaction")
	}

	logging.InitLogger("info", true)
	flow := &FirebaseFlowServer{
		host: "localhost:9010",
		c:    make(chan tokenSourceOrError, 10),
	}

	flow.startAndBlock()
}

func Test_DecodeUser(t *testing.T) {
	raw := `{
  "uid": "1234",
  "email": "john@acme.co",
  "emailVerified": true,
  "displayName": "john",
  "isAnonymous": false,
  "photoURL": "https://lh3.googleusercontent.com/a/1234",
  "providerData": [
    {
      "providerId": "google.com",
      "uid": "1234",
      "displayName": "John Doe",
      "email": "john@acme.co",
      "phoneNumber": null,
      "photoURL": "https://lh3.googleusercontent.com/a/AGNmyxaJzNUQkkTa7aXWzgnJvR6VbYLdNZz1WgtqBF-K1g=s96-c"
    },
    {
      "providerId": "password",
      "uid": "john@acme.com",
      "displayName": "John",
      "email": "john@acme.co",
      "phoneNumber": null,
      "photoURL": "https://lh3.googleusercontent.com/a/1234"
    }
  ],
  "stsTokenManager": {
    "refreshToken": "somerefresh",
    "accessToken": "sometoken",
    "expirationTime": 1677977898536
  },
  "createdAt": "1676041360990",
  "lastLoginAt": "1677974298497",
  "apiKey": "1234",
  "appName": "[DEFAULT]"
}
`

	user, err := decodeFirebaseUser([]byte(raw))
	if err != nil {
		t.Fatalf("Could not decode user; %v", err)
	}

	if user.UID != "1234" {
		t.Errorf("UID should be 1234; got %v", user.UID)
	}

	if user.StsTokenManager.AccessToken != "sometoken" {
		t.Errorf("AccessToken should be sometoken; got %v", user.StsTokenManager.AccessToken)
	}

	if user.StsTokenManager.RefreshToken != "somerefresh" {
		t.Errorf("RefreshToken should be somerefresh; got %v", user.StsTokenManager.RefreshToken)
	}
}
