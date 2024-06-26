package files

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

type LocalFileHelper struct{}

// NewReader creates a new Reader for local file.
func (h *LocalFileHelper) NewReader(uri string) (io.Reader, error) {
	schemePrefix := FileScheme + "://"
	uri = strings.TrimPrefix(uri, schemePrefix)
	reader, err := os.Open(uri)

	if err != nil {
		return nil, errors.WithStack(errors.Wrapf(err, "Could not read: %v", uri))
	}

	return reader, nil
}

// NewWriter creates a new Writer for the local file.
//
// TODO(jlewi): Can we add options to control filemode?
func (h *LocalFileHelper) NewWriter(uri string) (io.Writer, error) {
	_, err := os.Stat(uri)

	if err == nil || !os.IsNotExist(err) {
		return nil, errors.WithStack(errors.Errorf("Can't write %v; It already exists", uri))
	}

	writer, err := os.Create(uri)

	if err != nil {
		return nil, errors.WithStack(errors.Wrapf(err, "Could not write: %v", uri))
	}

	return writer, nil
}

// Exists checks whether the file exists.
func (h *LocalFileHelper) Exists(uri string) (bool, error) {
	_, err := os.Stat(uri)
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, nil
}

// Glob returns the list of files that match the pattern.
func (h *LocalFileHelper) Glob(uri string) ([]string, error) {
	return filepath.Glob(uri)
}

func (h *LocalFileHelper) Join(elem ...string) string {
	return filepath.Join(elem...)
}
