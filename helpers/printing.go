package helpers

import (
	"encoding/json"
	"fmt"
)

// PrettyString returns a prettily formatted string of the object.
func PrettyString(v interface{}) string {
	p, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("PrettyString returned error; %v", err)
	}
	return string(p)
}
