package main

import "testing"

func TestParseValidationMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want ValidationMode
	}{
		{"", ValidationOff},
		{"off", ValidationOff},
		{"disabled", ValidationOff},
		{"log", ValidationLog},
		{"audit", ValidationLog},
		{"enforce", ValidationEnforce},
		{"strict", ValidationEnforce},
		{" Enforce ", ValidationEnforce},
		{"LOG", ValidationLog},
	} {
		got, err := parseValidationMode(tc.in)
		if err != nil {
			t.Errorf("parseValidationMode(%q) = error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseValidationMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A misspelled mode must be refused rather than quietly read as "off": a
// resolver that believes it is validating and is not is worse than one that
// knows it is not.
func TestParseValidationModeRejectsNonsense(t *testing.T) {
	for _, in := range []string{"enforced", "yes", "true", "on"} {
		if _, err := parseValidationMode(in); err == nil {
			t.Errorf("parseValidationMode(%q) should be an error, not a silent off", in)
		}
	}
}

func TestIsInsecureZoneCoversTheZoneAndBelow(t *testing.T) {
	plugin := &PluginDNSSECValidate{insecureZones: []string{"broken.test.", "example.org."}}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"broken.test.", true},
		{"www.broken.test.", true},
		{"deep.down.broken.test.", true},
		{"example.org.", true},
		{"other.test.", false},
		{"test.", false},
		// The suffix must fall on a label boundary: this is a different zone
		// that merely ends in the same letters.
		{"notbroken.test.", false},
	} {
		if got := plugin.isInsecureZone(tc.name); got != tc.want {
			t.Errorf("isInsecureZone(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsInsecureZoneWithNoneConfigured(t *testing.T) {
	plugin := &PluginDNSSECValidate{}
	if plugin.isInsecureZone("anything.test.") {
		t.Error("no zones configured should mean nothing is exempt")
	}
}
