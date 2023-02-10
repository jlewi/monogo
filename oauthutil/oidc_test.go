package oauthutil

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_ParseClaims(t *testing.T) {
	type testCase struct {
		Data     string
		Expected CommonClaims
	}

	cases := []testCase{

		{
			Data: `{
  "at_hash": "rr0",
  "aud": "482251863780.apps.googleusercontent.com",
  "azp": "482251863780.apps.googleusercontent.com",
  "email": "john@domain.com",
  "email_verified": true,
  "exp": 1667502967,
  "family_name": "Doe",
  "given_name": "John",
  "hd": "domain.com",
  "iat": 1667499367,
  "iss": "https://accounts.google.com",
  "locale": "en",
  "name": "John Doe",
  "nonce": "KrRb3UWO6Hs7kZCGKWZjNg",
  "picture": "https://lh3.googleusercontent.com/a/ALm5wu36QMRxzVNKi-373TQEzprE9ZLUbyQLsISqw1Wq=s96-c",
  "sub": "1090"
}`,
			Expected: CommonClaims{
				AtHash:        "rr0",
				Aud:           "482251863780.apps.googleusercontent.com",
				AzP:           "482251863780.apps.googleusercontent.com",
				Email:         "john@domain.com",
				EmailVerified: true,
				Exp:           1667502967,
				FamilyName:    "Doe",
				GivenName:     "John",
				HD:            "domain.com",
				IAT:           1667499367,
				ISS:           "https://accounts.google.com",
				Locale:        "en",
				Name:          "John Doe",
				Nonce:         "KrRb3UWO6Hs7kZCGKWZjNg",
				Picture:       "https://lh3.googleusercontent.com/a/ALm5wu36QMRxzVNKi-373TQEzprE9ZLUbyQLsISqw1Wq=s96-c",
				Sub:           "1090",
			},
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			actual := &CommonClaims{}
			if err := json.Unmarshal([]byte(c.Data), actual); err != nil {
				t.Fatalf("Failed to unmarshal claims; error %v", err)
			}

			if d := cmp.Diff(c.Expected, *actual); d != "" {
				t.Errorf("Unexpected Diff:\n%v", d)
			}
		})
	}
}
