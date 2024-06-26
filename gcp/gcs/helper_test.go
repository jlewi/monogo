package gcs

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/api/iterator"
)

func TestParse(t *testing.T) {
	type testCase struct {
		Input         string
		ExpectedErrRe string
		Expected      *GcsPath
	}

	cases := []testCase{
		{
			Input:         "gs://bucket/folder1/file.csv",
			ExpectedErrRe: "",
			Expected: &GcsPath{
				Bucket: "bucket",
				Path:   "folder1/file.csv",
			},
		},
		{
			Input:         "gs://bucket",
			ExpectedErrRe: "",
			Expected: &GcsPath{
				Bucket: "bucket",
				Path:   "",
			},
		},
		{
			Input:         "gs://bucket/",
			ExpectedErrRe: "",
			Expected: &GcsPath{
				Bucket: "bucket",
				Path:   "",
			},
		},
		{
			Input:         "/some/path",
			ExpectedErrRe: ".*path.*doesn't.*match",
		},
	}

	for i, c := range cases {
		actual, err := Parse(c.Input)

		if c.ExpectedErrRe != "" {
			if err == nil {
				t.Errorf("Case %v: Expected error %v but no error returned", i, c.ExpectedErrRe)
				continue
			}

			if b, _ := regexp.MatchString(c.ExpectedErrRe, err.Error()); !b {
				t.Errorf("Case %v; Got error %v; want error matching %v", i, err, c.ExpectedErrRe)
			}
		}

		if err != nil && c.ExpectedErrRe == "" {
			t.Errorf("Case %v: Parse gave unexpected error: %v", i, err)
			continue
		}

		if d := cmp.Diff(c.Expected, actual); d != "" {
			t.Errorf("Case %v: Parse() mismatch (-want +got):\n%s", i, d)
			continue
		}
	}
}

type FakeObjectIterator struct {
	results []string
	pos     int
}

func (i *FakeObjectIterator) Next() (*storage.ObjectAttrs, error) {
	if i.pos >= len(i.results) {
		return nil, iterator.Done
	}

	p, err := Parse(i.results[i.pos])

	if err != nil {
		return nil, err
	}

	a := &storage.ObjectAttrs{
		Bucket: p.Bucket,
		Name:   p.Path,
	}
	i.pos = i.pos + 1
	return a, nil
}

func TestFindMatches(t *testing.T) {
	type testCase struct {
		Input    string
		Results  []string
		Expected []string
	}

	testCases := []testCase{
		{
			// N.B. This is a regex
			Input: "gs://mybucket/dirA/contract.*\\.pdf",
			Results: []string{
				"gs://mybucket/dirA/contract-1.pdf",
				"gs://mybucket/dirA/contract-2.pdf",
				"gs://mybucket/dirA/contract-2.csv",
				"gs://mybucket/dirA/other-1.pdf",
			},
			Expected: []string{
				"gs://mybucket/dirA/contract-1.pdf",
				"gs://mybucket/dirA/contract-2.pdf",
			},
		},
	}

	for i, c := range testCases {
		o := &FakeObjectIterator{
			results: c.Results,
			pos:     0,
		}

		pattern, err := Parse(c.Input)

		if err != nil {
			t.Errorf("Could not parse %v; error %v", c.Input, err)
		}

		actual, err := findMatches(pattern, o)

		if err != nil && err != iterator.Done {
			t.Errorf("findMatches returned error %v", err)
			continue
		}

		if d := cmp.Diff(c.Expected, actual); d != "" {
			t.Errorf("Case %v: Parse() mismatch (-want +got):\n%s", i, d)
			continue
		}
	}
}

func Test_Join(t *testing.T) {
	type testCase struct {
		Input    []string
		Expected string
	}

	cases := []testCase{
		{
			Input:    []string{"gs://bucket", "folder1", "file.csv"},
			Expected: "gs://bucket/folder1/file.csv",
		},
		{
			Input:    []string{"gs://bucket/folder1", "file.csv"},
			Expected: "gs://bucket/folder1/file.csv",
		},
		{
			Input:    []string{"gs://bucket/folder1/", "file.csv"},
			Expected: "gs://bucket/folder1/file.csv",
		},
	}

	h := &GcsHelper{}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			actual := h.Join(c.Input...)
			if d := cmp.Diff(c.Expected, actual); d != "" {
				t.Errorf("Join() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func Test_Glob(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("Skipping test in GitHub Actions")
	}

	files := []string{
		"gs://foyle-dev-mongo-testing/somefile/file-1.txt",
		"gs://foyle-dev-mongo-testing/somefile/file-2.txt",
		"gs://foyle-dev-mongo-testing/somefile/file-22.txt",
		"gs://foyle-dev-mongo-testing/somefile/otherfile.txt",
	}

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		t.Fatalf("Failed to create GCS storage client; error: %+v", err)
	}

	h := &GcsHelper{
		Ctx:    ctx,
		Client: client,
	}

	// Create the files
	for _, f := range files {
		w, err := h.NewWriter(f)
		if err != nil {
			t.Fatalf("Could not create writer for %v; error %v", f, err)
		}
		closer := w.(io.WriteCloser)
		if err := closer.Close(); err != nil {
			t.Fatalf("Could not close writer for %v; error %v", f, err)
		}
	}

	expected := []string{
		"gs://foyle-dev-mongo-testing/somefile/file-1.txt",
		"gs://foyle-dev-mongo-testing/somefile/file-2.txt",
	}

	actual, err := h.Glob("gs://foyle-dev-mongo-testing/somefile/file-?.txt")
	if err != nil {
		t.Fatalf("Glob returned error %v", err)
	}
	if d := cmp.Diff(expected, actual); d != "" {
		t.Errorf("Glob() mismatch (-want +got):\n%s", d)
	}
}
