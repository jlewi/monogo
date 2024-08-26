package helpers

import (
	"encoding/json"
	"testing"

	"github.com/pkg/errors"
)

type SomeError struct {
}

func (e *SomeError) Error() string {
	return "some error"
}

func Test_IsTypeError(t *testing.T) {
	type testCase struct {
		name   string
		input  error
		target error

		expected bool
	}

	cases := []testCase{
		{
			name:     "basic",
			input:    &SomeError{},
			target:   &SomeError{},
			expected: true,
		},
		{
			name:     "type error",
			input:    &SomeError{},
			target:   &json.SyntaxError{},
			expected: false,
		},
		{
			name:     "wrapped type error",
			input:    errors.Wrap(&SomeError{}, "wrapped"),
			target:   &SomeError{},
			expected: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsTypeError(tc.input, tc.target)
			if got != tc.expected {
				t.Errorf("expected %v; got %v", tc.expected, got)
			}
		})
	}
}

func Test_ListOfErrors(t *testing.T) {
	type testCase struct {
		name     string
		input    ListOfErrors
		expected string
	}

	cases := []testCase{
		{
			name: "basic",
			input: ListOfErrors{
				Final: errors.New("final"),
				Causes: []error{
					errors.New("cause 1"),
					errors.New("cause 2"),
				},
			},
			expected: "final; Causes: cause 1, cause 2",
		},
		{
			name: "no-final",
			input: ListOfErrors{
				Causes: []error{
					errors.New("cause 1"),
					errors.New("cause 2"),
				},
			},
			expected: "List of Errors: cause 1, cause 2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.input.Error()
			if got != tc.expected {
				t.Errorf("expected %v; got %v", tc.expected, got)
			}
		})
	}
}
