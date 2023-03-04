package oauthutil

import (
	"github.com/go-logr/zapr"
	"github.com/jlewi/p22h/backend/pkg/logging"
	"go.uber.org/zap"
	"os"
	"testing"
)

func Test_FirebaseFlowE2E(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("Skipping test because it requires user interaction")
	}

	logging.InitLogger("info", true)
	flow := &FirebaseFlowServer{
		log:  zapr.NewLogger(zap.L()),
		host: "localhost:9010",
		c:    make(chan tokenSourceOrError, 10),
	}

	flow.startAndBlock()
}
