package hostresolve

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		res  Result
		lb   string
		want string
	}{
		{
			// The split-DNS fix: internal zone says 10.x, but a
			// host-specific public record exists — external.
			name: "public answer beats split-horizon internal",
			res: Result{
				IPs: []string{"10.1.2.3"}, IsLocal: true,
				PublicIPs: []string{"193.160.1.10"},
			},
			want: ClassExternal,
		},
		{
			name: "public answer with only private addresses is internal",
			res: Result{
				PublicIPs: []string{"10.9.9.9"},
				Error:     "unresolvable",
			},
			want: ClassInternal,
		},
		{
			name: "wildcard-derived public answer defers to split-horizon",
			res: Result{
				IPs: []string{"10.1.2.3"}, IsLocal: true,
				PublicIPs: []string{"193.160.1.10"}, Wildcard: true,
			},
			want: ClassInternal,
		},
		{
			name: "wildcard with no split-horizon answer uses wildcard target",
			res: Result{
				Error:     "unresolvable",
				PublicIPs: []string{"193.160.1.10"}, Wildcard: true,
			},
			want: ClassExternal,
		},
		{
			name: "doh unavailable falls back to split-horizon verdict",
			res: Result{
				IPs: []string{"10.1.2.3"}, IsLocal: true,
				PublicError: publicErrUnavailable,
			},
			want: ClassInternal,
		},
		{
			name: "public nxdomain with public-pointing internal answer",
			res: Result{
				IPs: []string{"193.160.1.10"}, IsLocal: false,
				PublicError: publicErrUnresolvable,
			},
			want: ClassExternal,
		},
		{
			name: "no dns at all falls back to private lb ip",
			res:  Result{Error: "unresolvable", PublicError: publicErrUnavailable},
			lb:   "10.0.0.5,10.0.0.6",
			want: ClassInternal,
		},
		{
			name: "no dns at all falls back to public lb ip",
			res:  Result{Error: "unresolvable", PublicError: publicErrUnresolvable},
			lb:   "193.160.1.20",
			want: ClassExternal,
		},
		{
			name: "dns errored and no lb is unresolvable",
			res:  Result{Error: "unresolvable", PublicError: publicErrUnavailable},
			want: ClassUnresolvable,
		},
		{
			name: "empty result is pending",
			res:  Result{},
			want: ClassPending,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.res, tc.lb); got != tc.want {
				t.Fatalf("Classify(%+v, %q) = %q, want %q", tc.res, tc.lb, got, tc.want)
			}
		})
	}
}

func TestSameIPSet(t *testing.T) {
	if !sameIPSet([]string{"1.2.3.4", "5.6.7.8"}, []string{"5.6.7.8", "1.2.3.4"}) {
		t.Fatal("order must not matter")
	}
	if sameIPSet([]string{"1.2.3.4"}, []string{"1.2.3.4", "5.6.7.8"}) {
		t.Fatal("different lengths must not match")
	}
	if sameIPSet([]string{"1.2.3.4"}, []string{"5.6.7.8"}) {
		t.Fatal("different addresses must not match")
	}
}
