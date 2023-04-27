package oauthutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/jlewi/p22h/backend/pkg/logging"
)

func Test_IDToken(t *testing.T) {
	raw, err := os.ReadFile("/tmp/user.json")
	if err != nil {
		t.Fatalf("Could not read user.json; %v", err)
	}
	user := &FirebaseUser{}

	if err := json.Unmarshal(raw, user); err != nil {
		t.Fatalf("Could not unmarshal user; %v", err)
	}

	path := "https://securetoken.googleapis.com/v1/token"

	// https://firebase.google.com/docs/reference/rest/auth/#section-refresh-token
	params := url.Values{
		"key": []string{user.APIKey},
	}

	path = path + "?" + params.Encode()

	type RefreshRequest struct {
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
	}

	req := &RefreshRequest{
		GrantType:    "refresh_token",
		RefreshToken: user.StsTokenManager.RefreshToken,
	}

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(req); err != nil {
		t.Fatalf("Could not encode request; %v", err)
	}
	resp, err := http.Post(path, "application/json", &b)
	if err != nil {
		t.Fatalf("Could not post request; %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %v; got %v", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Could not read body; %v", err)
	}
	fmt.Printf("Body:\n%v", string(body))
}

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
