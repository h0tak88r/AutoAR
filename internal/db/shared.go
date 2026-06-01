package db

import "encoding/json"

// marshalPhaseJSON serializes a string slice to JSON. Returns "[]" for empty/nil input.
func marshalPhaseJSON(phases []string) string {
	if len(phases) == 0 {
		return "[]"
	}
	data, err := json.Marshal(phases)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// unmarshalPhaseJSON deserializes a JSON string into a string slice.
func unmarshalPhaseJSON(raw string, target *[]string) {
	if raw != "" && raw != "[]" {
		json.Unmarshal([]byte(raw), target)
	}
}
