package jwt

import (
	"testing"
	"time"
)

func TestNumericDate(t *testing.T) {
	// Reference date
	since1970 := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

	// Test cases
	tests := []struct {
		name     string
		input    time.Time
		expected time.Time
	}{
		{"Before 1970", time.Date(1960, time.January, 1, 0, 0, 0, 0, time.UTC), since1970},
		{"Exact 1970", since1970, since1970},
		{"After 1970", time.Date(2024, time.November, 30, 15, 0, 0, 0, time.UTC), time.Date(2024, time.November, 30, 15, 0, 0, 0, time.UTC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwtTime := NumericDate(tt.input)
			if !jwtTime.Equal(tt.expected) {
				t.Errorf("got %v, expected %v", jwtTime, tt.expected)
			}
		})
	}
}

func TestMarshalJSON(t *testing.T) {
	// Reference date
	since1970 := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

	// Test cases
	tests := []struct {
		name        string
		input       *JWTTime
		expected    string
		expectError bool
	}{
		{"Before 1970", &JWTTime{since1970.Add(-time.Hour)}, "null", false},
		{"Exact 1970", &JWTTime{since1970}, "0", false},
		{"After 1970", &JWTTime{since1970.Add(time.Hour)}, "3600", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := tt.input.MarshalJSON()
			if (err != nil) != tt.expectError {
				t.Fatalf("unexpected error status: %v", err)
			}

			if string(jsonData) != tt.expected {
				t.Errorf("got %s, expected %s", string(jsonData), tt.expected)
			}
		})
	}
}

func TestUnmarshalJSON(t *testing.T) {
	// Reference date
	since1970 := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

	// Test cases
	tests := []struct {
		name        string
		input       string
		expected    time.Time
		expectError bool
	}{
		{"Valid Unix timestamp", "3600", since1970.Add(time.Hour), false},
		{"Zero timestamp", "0", since1970, false},
		{"Invalid JSON", `"invalid"`, time.Time{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var jwtTime JWTTime
			err := jwtTime.UnmarshalJSON([]byte(tt.input))

			if (err != nil) != tt.expectError {
				t.Fatalf("unexpected error status: %v", err)
			}

			if !tt.expectError && !jwtTime.Equal(tt.expected) {
				t.Errorf("got %v, expected %v", jwtTime, tt.expected)
			}
		})
	}
}
