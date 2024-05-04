package logging

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"cloud.google.com/go/logging"
	"cloud.google.com/go/logging/logadmin"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/api/iterator"
)

const (
	testLogName = "sinkTest"
	runIDLabel  = "runID"
)

func Test_Sink(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skipf("Test is skipped in GitHub actions")
	}
	project := "foyle-dev"

	runID := uuid.NewString()
	labels := map[string]string{
		"testLabel": "testValue",
		runIDLabel:  runID,
	}

	if err := RegisterSink(project, testLogName, labels); err != nil {
		t.Fatalf("Failed to register the sink: %v", err)
	}

	logr, err := newLogger()
	if err != nil {
		t.Fatalf("Failed to create the logger: %v", err)
	}

	logr.Info("latest message", "field1", "value")

	logr.Error(errors.New("some error"), "Try writing an error", "field1", "value")

	queryLabels := map[string]string{}
	for k, v := range labels {
		// Need to prepend "labels."
		queryLabels["labels."+k] = v
	}
	link := GetLink(project, queryLabels)

	t.Logf("Stackdriver link: %v", link)

	// Flush logs before exiting
	// https://pkg.go.dev/go.uber.org/zap#Logger.Sync
	if err := zap.L().Sync(); err != nil {
		// Ignore any errors about sync'ing stdout
		if !strings.Contains(err.Error(), "sync /dev/stdout") {
			t.Fatalf("Could not sync logs: %v", err)
		}
	}

	// Set this to true if you want to open the link in a browser
	if false {
		if err := browser.OpenURL(link); err != nil {
			t.Errorf("Could not open URL: %v", err)
		}
	}

	adminClient, err := logadmin.NewClient(context.Background(), project)

	if err != nil {
		log.Fatalf("Failed to create logadmin client: %v", err)
	}
	defer adminClient.Close()

	numExpected := 2
	entries, err := readLogs(adminClient, project, runID, numExpected, 5*time.Minute)

	if err != nil {
		t.Fatalf("Error getting entries: %v", err)
	}

	for _, entry := range entries {
		t.Logf("Entry: %v", entry)
	}

	// N.B. the diagnostic log entry that shows up in the log doesn't show up here because it uses a different log name
	// projects/${PROJECT}/logs/diagnostic-log"
	if len(entries) != numExpected {
		t.Fatalf("Incorrect number of log entries; want %d got %d", numExpected, len(entries))
	}
}

func newLogger() (logr.Logger, error) {
	// We need to use a production config because we want to use the JSON encoder
	c := zap.NewProductionConfig()
	// Configure the encoder to use the fields Cloud Logging expects.
	// https://cloud.google.com/logging/docs/structured-logging
	c.EncoderConfig.LevelKey = SeverityField
	c.EncoderConfig.TimeKey = TimeField
	c.EncoderConfig.MessageKey = "message"
	c.Level = zap.NewAtomicLevelAt(zap.DebugLevel)

	stackdriver := Scheme + ":///loggingsink/test"
	c.OutputPaths = []string{"stdout", stackdriver}

	newLogger, err := c.Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build zap logger; error %v", err))
	}

	zap.ReplaceGlobals(newLogger)

	logR := zapr.NewLogger(newLogger)
	return logR, nil
}

// readLogs reads the most recent log entries.
func readLogs(client *logadmin.Client, projectID string, runID string, minExpected int, timeout time.Duration) ([]*logging.Entry, error) {
	ctx := context.Background()

	endTime := time.Now().Add(timeout)
	pollTime := 10 * time.Second
	for {
		var entries []*logging.Entry

		iter := client.Entries(ctx,
			// Get the log entries for this run.
			logadmin.Filter(fmt.Sprintf(`logName = "projects/%s/logs/%s" AND labels.%s = "%s"`, projectID, testLogName, runIDLabel, runID)),
			// Get most recent entries first.
			logadmin.NewestFirst(),
		)

		// Fetch the most recent entries.
		for len(entries) < 2*minExpected {
			entry, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
		if len(entries) >= minExpected {
			return entries, nil
		}

		if time.Now().Add(pollTime).After(endTime) {
			return nil, errors.New("Timed out waiting for entries")
		}
		time.Sleep(pollTime)
	}
}

func Test_ParseURI(t *testing.T) {
	type testCase struct {
		Input   string
		Project string
		LogName string
		IsURI   bool
	}

	cases := []testCase{
		{
			Input:   "gcplogs:///projects/foyle-dev/logs/sinkTest",
			Project: "foyle-dev",
			LogName: "sinkTest",
			IsURI:   true,
		},
		{
			Input:   "/projects/foyle-dev/logs/sinkTest/some/extra/path",
			Project: "",
			LogName: "",
			IsURI:   false,
		},
		{
			Input:   "gcplogs:///projects/foyle-dev/logs/sinkTest/some/extra/path",
			Project: "",
			LogName: "",
			IsURI:   false,
		},
	}

	for _, c := range cases {
		t.Run(c.Input, func(t *testing.T) {
			project, logName, isURI := ParseURI(c.Input)
			if project != c.Project {
				t.Errorf("Project: got %v, want %v", project, c.Project)
			}
			if logName != c.LogName {
				t.Errorf("LogName: got %v, want %v", logName, c.LogName)
			}
			if isURI != c.IsURI {
				t.Errorf("IsURI: got %v, want %v", isURI, c.IsURI)
			}
		})
	}
}
