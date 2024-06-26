package gcs

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"path"
	"path/filepath"
	"regexp"

	"cloud.google.com/go/storage"
	"github.com/go-logr/zapr"
	"github.com/jlewi/monogo/util"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/api/iterator"
)

var (
	gcsRe *regexp.Regexp
)

type GcsPath struct {
	Bucket string
	Path   string
}

func (p *GcsPath) ToURI() string {
	r := "gs://" + p.Bucket
	if p.Path != "" {
		r = r + "/" + p.Path
	}
	return r
}

func Parse(path string) (*GcsPath, error) {
	m := gcsRe.FindStringSubmatch(path)

	if m == nil {
		return nil, fmt.Errorf("Path %v; doesn't match regex %v", path, gcsRe.String())
	}

	r := &GcsPath{}

	if len(m) >= 2 {
		r.Bucket = m[1]
	}

	if len(m) >= 3 {
		r.Path = m[2]
	}
	return r, nil
}

type GcsHelper struct {
	Ctx    context.Context
	Client *storage.Client
}

// NewReader creates a new Reader for GCS path or local file.
func (h *GcsHelper) NewReader(uri string) (io.Reader, error) {
	p, err := Parse(uri)
	if err != nil {
		return nil, err
	}
	b := h.Client.Bucket(p.Bucket)
	o := b.Object(p.Path)

	reader, err := o.NewReader(h.Ctx)

	if err != nil {
		return nil, errors.WithStack(errors.Wrapf(err, "Clould not read: %v", uri))
	}

	return reader, nil
}

// NewWriter creates a new Writer for GCS path or local file.
//
// TODO(jlewi): Can we add options to control filemode?
func (h *GcsHelper) NewWriter(uri string) (io.Writer, error) {
	p, err := Parse(uri)
	if err != nil {
		return nil, err
	}
	b := h.Client.Bucket(p.Bucket)

	_, err = b.Attrs(h.Ctx)
	if err != nil {
		return nil, errors.WithStack(errors.Wrapf(err, "Can't access bucket %v; It may not exist", p.Bucket))
	}

	o := b.Object(p.Path)

	return o.NewWriter(h.Ctx), nil
}

// Exists checks whether the URI exists.
//
// If error is not nil the boolean value will be random.
func (h *GcsHelper) Exists(uri string) (bool, error) {
	// In the event of an error we return a random value for the boolean.
	// This is meant to discourage callers from trusting the value in the event an error occured.
	randVal := rand.Float32() > .5

	p, err := Parse(uri)
	if err != nil {
		return randVal, err
	}
	b := h.Client.Bucket(p.Bucket)

	_, err = b.Attrs(h.Ctx)

	if err != nil {
		isMatch, _ := regexp.MatchString(".*doesn't.*exist.*", err.Error())

		if isMatch {
			return true, nil
		}

		return randVal, err
	}

	o := b.Object(p.Path)

	return ObjectExists(h.Ctx, o), nil
}

// Glob lists all objects matching some glob expression.

func (h *GcsHelper) Glob(uri string) ([]string, error) {
	paths := []string{}
	p, err := Parse(uri)
	if err != nil {
		return paths, errors.WithStack(errors.Wrapf(err, "Could not glob objects matching %v", uri))
	}

	b := h.Client.Bucket(p.Bucket)

	q := &storage.Query{
		MatchGlob: p.Path,
	}

	objs := b.Objects(h.Ctx, q)

	for {
		i, err := objs.Next()

		if err == iterator.Done {
			return paths, nil
		}

		if err != nil {
			return paths, errors.WithStack(errors.Wrapf(err, "Error getting next object matching %v", uri))
		}

		iPath := GcsPath{
			Bucket: i.Bucket,
			Path:   i.Name,
		}

		paths = append(paths, iPath.ToURI())
	}
}

// BuildInputOutputList builds a map from input files to the files that they
// should be mapped to.
//
// input is a regex as specified by TransformFiles. This is used to find existing files and generate
// the corresponding output files.
func (h *GcsHelper) BuildInputOutputList(input string, output string) (map[string]string, error) {
	paths, err := ListObjects(h.Ctx, h.Client, input)

	if err != nil {
		return map[string]string{}, errors.Wrapf(err, "Could not list files matching: %v", input)
	}
	return util.TransformFiles(paths, input, output)
}

func (h *GcsHelper) Join(elem ...string) string {
	uri, err := Parse(elem[0])
	log := zapr.NewLogger(zap.L())
	if err != nil {
		log.Error(err, "Failed to parse URI", "uri", elem[0])
		// Just fallback to using filepath.Join
		// The parse error likely means its not a GCS URI
		return filepath.Join(elem...)
	}

	pieces := []string{uri.Path}
	pieces = append(pieces, elem[1:]...)
	uri.Path = path.Join(pieces...)
	return uri.ToURI()
}

func ObjectExists(ctx context.Context, o *storage.ObjectHandle) bool {
	log := zapr.NewLogger(zap.L())
	_, err := o.Attrs(ctx)

	if err == nil {
		return true
	}

	isMatch, mErr := regexp.MatchString(".*doesn't.*exist.*", err.Error())

	if mErr != nil {
		log.Error(err, "There was a problem matching the regex; %v")
	}

	if err != nil && isMatch {
		return false
	}

	return true
}

// ListObjects lists all objects matching some regex.
//
// This is listing all files in the parent directory.
func ListObjects(ctx context.Context, client *storage.Client, uri string) ([]string, error) {
	paths := []string{}
	p, err := Parse(uri)
	if err != nil {
		return paths, errors.WithStack(errors.Wrapf(err, "Could not list objects matching %v", uri))
	}

	b := client.Bucket(p.Bucket)

	prefix := path.Dir(p.Path)

	q := &storage.Query{
		Delimiter: "/",
		Prefix:    prefix + "/",
		Versions:  false,
	}

	objs := b.Objects(ctx, q)
	return findMatches(p, objs)
}

// ListObjectsWithPrefix returns a list of all GCS objects within the given prefix.
func ListObjectsWithPrefix(ctx context.Context, client *storage.Client, prefix string) ([]string, error) {
	paths := []string{}
	p, err := Parse(prefix)
	if err != nil {
		return paths, errors.WithStack(errors.Wrapf(err, "Could not list objects matching %v", prefix))
	}

	b := client.Bucket(p.Bucket)

	q := &storage.Query{
		Prefix:   p.Path,
		Versions: false,
	}

	objs := b.Objects(ctx, q)

	for {
		i, err := objs.Next()

		if err == iterator.Done {
			return paths, nil
		}

		if err != nil {
			return paths, errors.WithStack(errors.Wrapf(err, "Error getting next object with prefix %v", prefix))
		}

		// Skip it is just a prefix
		if i.Prefix != "" {
			continue
		}

		iPath := GcsPath{
			Bucket: i.Bucket,
			Path:   i.Name,
		}

		paths = append(paths, iPath.ToURI())

	}
}

type objectAttrsIterator interface {
	Next() (*storage.ObjectAttrs, error)
}

func findMatches(pattern *GcsPath, objs objectAttrsIterator) ([]string, error) {
	log := zapr.NewLogger(zap.L())
	paths := []string{}
	for {
		i, err := objs.Next()

		if err == iterator.Done {
			return paths, nil
		}

		if err != nil {
			return paths, errors.WithStack(errors.Wrapf(err, "Error getting next object matching %v", pattern.ToURI()))
		}

		// Skip it is just a prefix
		if i.Prefix != "" {
			continue
		}

		iPath := GcsPath{
			Bucket: i.Bucket,
			Path:   i.Name,
		}

		log.V(1).Info("path.Match", "pattern", pattern.ToURI(), "path", iPath.ToURI())
		isMatch, err := regexp.MatchString(pattern.ToURI(), iPath.ToURI())

		if err != nil {
			log.Error(err, "path.Match", "pattern", pattern.ToURI(), "path", iPath.ToURI())
			continue
		}

		if isMatch {
			paths = append(paths, iPath.ToURI())
		}
	}
}

func init() {
	gcsRe = regexp.MustCompile("gs://([^/]+)/{0,1}(.*)")
}
