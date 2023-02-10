package helpers

import "reflect"

// StructToMap returns a dictionary mapping fieldNames to values
func StructToMap(s any) (map[string]any, error) {
	result := map[string]any{}

	rowType := reflect.Indirect(reflect.ValueOf(s))

	for i := 0; i < rowType.Type().NumField(); i = i + 1 {
		field := rowType.Field(i)
		name := rowType.Type().Field(i).Name
		result[name] = field.Interface()
	}

	return result, nil
}
