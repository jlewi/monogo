package helpers

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_StructToMap(t *testing.T) {
	type testCase struct {
		input    any
		expected map[string]any
	}

	type SomeStruct struct {
		Field1 string
		Field2 int
	}

	cases := []testCase{
		{
			input: &SomeStruct{
				Field1: "hello",
				Field2: 2,
			},
			expected: map[string]any{
				"Field1": "hello",
				"Field2": 2,
			},
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("Case %d", i), func(t *testing.T) {
			actual, err := StructToMap(c.input)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if d := cmp.Diff(c.expected, actual); d != "" {
				t.Errorf("Unexpected diff:\n%s", d)
			}
		})
	}
}
