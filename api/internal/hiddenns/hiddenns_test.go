package hiddenns

import "testing"

func TestValidatePattern(t *testing.T) {
	valid := []string{"nhn-scam", "nhn-*", "kube-*", "*-system", "a", "cattle-*-system"}
	for _, p := range valid {
		if err := ValidatePattern(p); err != nil {
			t.Errorf("ValidatePattern(%q) = %v, want nil", p, err)
		}
	}
	invalid := []string{"", "*", "**", "NHN-scam", "nhn scam", "nhn_scam", "-leading", "trailing-", "a%b", "ns/sub"}
	for _, p := range invalid {
		if err := ValidatePattern(p); err == nil {
			t.Errorf("ValidatePattern(%q) = nil, want error", p)
		}
	}
}

func TestExclusionSQL(t *testing.T) {
	sql, args := ExclusionSQL("he.namespace", nil)
	if sql != "" || args != nil {
		t.Errorf("empty patterns: got %q %v", sql, args)
	}

	sql, args = ExclusionSQL("he.namespace", []string{"nhn-scam", "nhn-ror"})
	if sql != "he.namespace NOT IN (?,?)" {
		t.Errorf("exact patterns: got %q", sql)
	}
	if len(args) != 2 || args[0] != "nhn-scam" || args[1] != "nhn-ror" {
		t.Errorf("exact args: got %v", args)
	}

	sql, args = ExclusionSQL("cii.namespace", []string{"kube-*", "nhn-scam"})
	if sql != "cii.namespace NOT IN (?) AND cii.namespace NOT LIKE ?" {
		t.Errorf("mixed patterns: got %q", sql)
	}
	if len(args) != 2 || args[0] != "nhn-scam" || args[1] != "kube-%" {
		t.Errorf("mixed args: got %v", args)
	}
}

func TestMatcherFor(t *testing.T) {
	match := MatcherFor([]string{"nhn-scam", "kube-*"})
	cases := map[string]bool{
		"nhn-scam":    true,
		"kube-system": true,
		"kube-public": true,
		"nhn-ror":     false,
		"my-app":      false,
		"":            false,
	}
	for ns, want := range cases {
		if got := match(ns); got != want {
			t.Errorf("match(%q) = %v, want %v", ns, got, want)
		}
	}
	never := MatcherFor(nil)
	if never("anything") {
		t.Error("empty matcher should never match")
	}
}
