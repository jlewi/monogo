package helpers

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

// IgnoreError is a helper function to deal with errors.
func IgnoreError(err error) {
	if err == nil {
		return
	}
	log := zapr.NewLogger(zap.L())
	log.Error(err, "Unexpected error occurred")
}

// DeferIgnoreError is a helper function to ignore errors returned by functions called with defer.
func DeferIgnoreError(f func() error) {
	IgnoreError(f())
}

// MatchError is a function for matching errors. Returns empty string if no match
type MatchError func(err error) string

func NilError(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("Want nil error; got %v", err)
}

// IsTypeError returns true if the error is of type TypeError or if any of the causes is of the given type.
// This is different from errors.Is because errors.Is relies on the Is interface being implemented for errors
// which isn't the case for many errors. This method uses reflect to compare error types.
func IsTypeError(err error, target error) bool {
	if target == nil {
		return err == target
	}

	rType := reflect.Indirect(reflect.ValueOf(target))
	expected := rType.Type()

	for {
		actual := reflect.Indirect(reflect.ValueOf(err)).Type()
		convertable := actual.ConvertibleTo(expected)

		if convertable {
			return true
		}
		if err = errors.Unwrap(err); err == nil {
			return false
		}
	}
}

// ListOfErrors is used when we want to return more then one error.
// This happens when we want to keep going and accumulate errors
type ListOfErrors struct {
	Causes []error
	Final  error
}

// Error returns a single error wrapping all the errors.
func (l *ListOfErrors) Error() string {
	m := ""
	if l.Final != nil {
		m += l.Final.Error() + "; Causes: "
	} else {
		m += "List of Errors: "
	}

	c := make([]string, 0, len(l.Causes))
	for _, i := range l.Causes {
		c = append(c, i.Error())
	}

	m = m + strings.Join(c, ", ")
	return m
}

// AddCause adds an error to the list.
func (l *ListOfErrors) AddCause(e error) {
	l.Causes = append(l.Causes, e)
}

// NewTypeErrorMatcher creates a new MatchError function that matches errors of the given type.
func NewTypeErrorMatcher(target error) MatchError {
	return func(err error) string {
		if IsTypeError(err, target) {
			return ""
		}
		return fmt.Sprintf("Want error of type %T; got %T", target, err)
	}
}
