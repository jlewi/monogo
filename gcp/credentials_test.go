package gcp

import (
	"os"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/api/gmail/v1"
)

func Test_WebFlowHelepr(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("Skipping test in GitHub Actions")
	}
	dLog, err := zap.NewDevelopmentConfig().Build()
	if err != nil {
		t.Fatalf("Error creating logger: %v", err)
	}
	zap.ReplaceGlobals(dLog)

	clientSecret := "/Users/jlewi/secrets/gctl.oauthclientid.foyle-dev.json"
	flow, err := NewWebFlowHelper(clientSecret, []string{gmail.GmailReadonlyScope})
	if err != nil {
		t.Fatalf("Error creating web flow helper: %v", err)
	}

	ts, err := flow.Run()
	if err != nil {
		t.Fatalf("Error getting token source: %v", err)
	}

	if _, err := ts.Token(); err != nil {
		t.Fatalf("Error getting token: %v", err)
	}
}
