package files

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jlewi/monogo/helpers"

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
// N.B. Prior to 2024/08/26 this function would return an error if the file already existed. This behavior was changed
// so that the file is truncated if it already exists. If the caller doesn't want to overwrite it, they should
// use exists to check if the file exists before calling this function. This change was made because we want to
// support truncation.
func (h *LocalFileHelper) NewWriter(uri string) (io.Writer, error) {
	dir := filepath.Dir(uri)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, helpers.UserGroupAllPerm); err != nil {
			return nil, errors.WithStack(errors.Wrapf(err, "Could not create directory: %v", dir))
		}
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
