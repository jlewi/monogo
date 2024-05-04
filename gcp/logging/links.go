package logging

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// GetLink returns a link to the Cloud Logging console that shows logs matching the given labels.
// The link isn't stable because it doesn't pin the time.
func GetLink(project string, labels map[string]string) string {
	labels["resource.labels.project_id"] = project

	path := "https://console.cloud.google.com/logs/query"
	path += ";query=" + buildLabelsQuery(labels)

	query := url.Values{
		"project": []string{project},
	}

	return path + "?" + query.Encode()
}

func buildLabelsQuery(labels map[string]string) string {
	// We want the names to appear in sorted order in the link so the link is deterministic.
	names := make([]string, 0, len(labels))
	for n := range labels {
		names = append(names, n)
	}
	sort.Strings(names)

	labelsQuery := []string{}
	for _, n := range names {
		labelsQuery = append(labelsQuery, fmt.Sprintf(`%s="%s"`, n, labels[n]))
	}
	return url.QueryEscape(strings.Join(labelsQuery, "\n"))
}

// GetLinkAroundTime returns a link to the logs query pinned at the specified time.
// It will show a time window specified by the duration around the time.
// Duration is rounded to the nearest second, minute or hour depending on its size
func GetLinkAroundTime(project string, labels map[string]string, t time.Time, duration time.Duration) string {
	labels["resource.labels.project_id"] = project

	path := "https://console.cloud.google.com/logs/query"
	path += ";query=" + buildLabelsQuery(labels)

	// Pin to a time window centered at time t and +- duration. This creates a stable link to the log entries
	size, units := roundDuration(duration)
	window := fmt.Sprintf("PT%2.f%s", size, units)

	// CursorTimestamp controls the cursor position in the UI; if we don't set it it complains about
	// the query being invalid when you scroll down.
	path += ";cursorTimestamp=" + t.Format(time.RFC3339)
	path += ";aroundTime=" + t.Format(time.RFC3339)
	path += ";duration=" + url.QueryEscape(window)

	query := url.Values{
		"project": []string{project},
	}

	// Return the URL as a string
	return path + "?" + query.Encode()
}

// roundDuration rounds the duration to the time and units used in cloud logging queries
func roundDuration(duration time.Duration) (float64, string) {
	size := 1.0
	units := "H"
	if duration >= time.Hour {
		size = duration.Round(time.Hour).Hours()
		units = "H"
	}

	if duration < time.Hour && duration >= 5*time.Minute {
		size = duration.Round(time.Minute).Minutes()
		units = "M"
	}

	if duration < 5*time.Minute {
		size = duration.Round(time.Second).Seconds()
		units = "S"
	}

	return size, units
}
