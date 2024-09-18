package files

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func Test_LocalNewWriter(t *testing.T) {
	tDir, err := os.MkdirTemp("", "testLocalNewWriter")
	if err != nil {
		t.Fatalf("Error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tDir)

	type testCase struct {
		name  string
		input string
	}

	cases := []testCase{
		{
			// Ensure directory is created if it doesn't already exist
			name:  "basic",
			input: filepath.Join(tDir, "test.txt"),
		},
		{
			// Ensure directory is created if it doesn't already exist
			name:  "createdir",
			input: filepath.Join(tDir, "newDir/test.txt"),
		},
	}

	h := &LocalFileHelper{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, err := h.NewWriter(c.input)
			if err != nil {
				t.Fatalf("NewWriter() error: %v", err)
			}

			if _, err := w.Write([]byte("test")); err != nil {
				t.Fatalf("Write() error: %v", err)
			}

			closer, ok := w.(io.Closer)
			if !ok {
				t.Fatalf("Writer is not a Closer")
			}
			if err := closer.Close(); err != nil {
				t.Fatalf("Close() error: %v", err)
			}

			if _, err := os.Stat(c.input); err != nil {
				t.Errorf("Stat() error: %v", err)
			}
		})
	}
}
