package logging

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"time"

	"cloud.google.com/go/logging"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	Scheme        = "gcplogs"
	SeverityField = "severity"
	TimeField     = "time"

	// TraceField is the field Google Cloud Logging looks for the
	// trace https://cloud.google.com/logging/docs/structured-logging
	TraceField = "logging.googleapis.com/trace"
)

// RegisterSink registers Sink as a zap sink; this allows zap to send logs to Cloud Logging.
//
// project is the GCP project
// name is the name of the log to use
// labels are labels to add to every log entry
func RegisterSink(project string, name string, labels map[string]string) error {
	var ctx = context.Background() // Sets your Google Cloud Platform project ID.

	client, err := logging.NewClient(ctx, project)
	if err != nil {
		log.Fatalf("Failed to create Cloud Logging client: %v", err)
	}

	logger := client.Logger(name, logging.CommonLabels(labels))

	sink := &Sink{
		Client: client,
		Logger: logger,
	}

	return zap.RegisterSink(Scheme, func(u *url.URL) (zap.Sink, error) {
		return sink, nil
	})
}

// Sink implements zap.Sink interface. This lets zap send logs to Cloud Logging.
//
// To use the sink:
//
//  1. Call RegisterSink; this will register register the sink with zap
//
//  2. Create a zap logger configuration in which the output path uses the URL
//     gcplogs:///projects/${PROJECT}/logs/${LOGNAME}
//
//     For example:
//     c. := zap.NewProductionConfig()
//     c.OutputPaths = []string{"gcplogs:///projects/${PROJECT}/logs/${LOGNAME}", "stdout"}
type Sink struct {
	// Set client if you want the sink to take ownership of the client and call close
	// If you don't then you must call Client.Close to flush the logs
	Client *logging.Client
	Logger *logging.Logger
}

func (s *Sink) Write(in []byte) (n int, err error) {
	reader := bytes.NewReader(in)
	// Create a scanner to read the data line by line
	scanner := bufio.NewScanner(reader)

	bytesRead := 0

	for scanner.Scan() {
		line := scanner.Bytes()

		payload := map[string]interface{}{}

		entry := logging.Entry{}

		if err := json.Unmarshal(line, &payload); err == nil {
			entry.Payload = payload

			// We need to explicitly copy special fields out of the arbitrary payload into the Cloud Logging fields.
			// Otherwise that won't receive special treatment and show up in the UI.
			// For example, we need to explicitly copy the severity field so that in Cloud Logging we can filter
			// by the severity field.
			if severityVal, ok := payload[SeverityField]; ok {
				if severity, ok := severityVal.(string); ok {
					entry.Severity = logging.ParseSeverity(severity)
				}
			}

			if timeInterface, ok := payload[TimeField]; ok {
				if timeVal, ok := timeInterface.(float64); ok {
					// We need to convert the float timestamp into a unix timestamp
					seconds := int64(timeVal)
					fractional := timeVal - float64(seconds)
					nanoseconds := int64(fractional * 1e9)

					entry.Timestamp = time.Unix(seconds, nanoseconds)
				}
			}

			// If the trace field is present we need to copy it out of the payload and into the entry and delete
			// the entry in the payload.
			if traceVal, ok := payload[TraceField]; ok {
				entry.Trace = traceVal.(string)
				delete(payload, TraceField)
			}
		} else {
			entry.Payload = string(line)
		}
		// Log sends the records to GCP asynchronously; its non-blocking
		s.Logger.Log(entry)
		bytesRead += len(line)
		// N.B. The newline gets stripped so we need to add 1
		bytesRead += 1
	}

	if err := scanner.Err(); err != nil {
		return bytesRead, err
	}

	if bytesRead != len(in) {
		return bytesRead, errors.New(fmt.Sprintf("Unexpect number of bytes read. Expected to read %d bytes but only read %d", len(in), bytesRead))
	}

	return bytesRead, nil
}

func (s *Sink) Close() error {
	return s.Client.Close()
}

// Sync flushes any buffers in the logger.
func (s *Sink) Sync() error {
	return s.Logger.Flush()
}
