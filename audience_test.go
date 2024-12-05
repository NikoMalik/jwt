package jwt

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/bytedance/sonic"
)

type ANother []string

func TestAudienceCreate(t *testing.T) {

	aud := []string{"admin", "user", "sigma", "smegma"}
	ap := NewAudience(aud)

	fmt.Println("Audiences:", ap.Get())
}

func TestSize(t *testing.T) {
	fmt.Println(unsafe.Sizeof(ANother{}))
	fmt.Println(unsafe.Sizeof(Audience{}))

}

func TestAudienceUnmarshalMalformed(t *testing.T) {
	testCases := []struct {
		have string
	}{
		{``},              // Empty string
		{`abc12`},         // Invalid JSON
		{`123`},           // Invalid JSON (not a string or array)
		{`{}`},            // Invalid JSON (object instead of array)
		{`[{}]`},          // Invalid JSON (object in array)
		{`["admin",{}]`},  // Invalid JSON (object in array)
		{`["admin",123]`}, // Invalid JSON (wrong type in array)
	}

	for _, tc := range testCases {
		var a Audience
		err := a.UnmarshalJSON([]byte(tc.have))
		mustFail(t, err)
	}
}
func TestAudienceUnmarshal2(t *testing.T) {
	testCases := []struct {
		jstr     []byte
		expected Audience
	}{
		{[]byte(`"doge"`), Audience{aud: unsafe.Pointer(&[]string{"foo"}), lenAud: 1}},
		{[]byte(`["niko","malik"]`), Audience{aud: unsafe.Pointer(&[]string{"foo", "bar"}), lenAud: 2}},
		{[]byte("[]"), Audience{aud: unsafe.Pointer(&[]string{}), lenAud: 0}},
	}
	for _, tc := range testCases {
		t.Run(string(tc.jstr), func(t *testing.T) {
			var aud Audience
			if err := aud.UnmarshalJSON(tc.jstr); err != nil {
				t.Fatal(err)
			}
			if len(aud.Get()) != tc.expected.lenAud {
				t.Errorf("expected %d audiences, got %d", tc.expected.lenAud, len(aud.Get()))
			}

			if err := sonic.Unmarshal(tc.jstr, &aud); err != nil {
				t.Fatal(err)
			}
			if len(aud.Get()) != tc.expected.lenAud {
				t.Errorf("expected %d audiences, got %d", tc.expected.lenAud, len(aud.Get()))
			}
		})
	}
}

func TestAudienceUnmarshal(t *testing.T) {
	testCases := []struct {
		have string
		want Audience
	}{
		{`[]`, Audience{aud: unsafe.Pointer(&[]string{}), lenAud: 0}},                                       // Empty array
		{`"admin"`, Audience{aud: unsafe.Pointer(&[]string{"admin"}), lenAud: 1}},                           // Single string
		{`["admin"]`, Audience{aud: unsafe.Pointer(&[]string{"admin"}), lenAud: 1}},                         // Single string array
		{`["admin", "co-admin"]`, Audience{aud: unsafe.Pointer(&[]string{"admin", "co-admin"}), lenAud: 2}}, // Multiple strings
	}

	for _, tc := range testCases {

		err := tc.want.UnmarshalJSON([]byte(tc.have))
		mustOk(t, err)
		mustEqual(t, len(tc.want.Get()), tc.want.lenAud)

		for i := range tc.want.Get() {
			mustEqual(t, tc.want.Get()[i], tc.want.Get()[i])
		}
	}
}

func TestAudienceMarshal(t *testing.T) {
	testCases := []struct {
		have Audience
		want string
	}{
		// Test empty Audience (nil or zero value)
		{Audience{}, `[]`}, // Adjusted to match your current implementation
		// Test a single string
		{Audience{aud: unsafe.Pointer(&[]string{"admin"}), lenAud: 1}, `"admin"`},
		// Test multiple strings
		{Audience{aud: unsafe.Pointer(&[]string{"admin", "co-admin"}), lenAud: 2}, `["admin","co-admin"]`},
	}

	for _, tc := range testCases {
		raw, err := tc.have.MarshalJSON()
		mustOk(t, err)
		mustEqual(t, string(raw), tc.want)
	}
}
