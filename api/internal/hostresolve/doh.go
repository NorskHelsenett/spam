package hostresolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
)

// DNS-over-HTTPS gives the worker a *public* DNS vantage point. The
// primary resolver is the pod's (split-horizon) resolver, which answers
// with the internal zone record — so a host that also has a public
// record used to classify as internal, silently under-reporting
// exposure. Plain DNS to a public resolver is not an option (outbound
// :53 is blocked in most of our environments), but 443 egress is
// generally open, so the public view rides on the dns-json dialect
// (GET ?name=&type= with Accept: application/dns-json).
//
// Privacy note: every exposed hostname is sent to the DoH provider.
// Operators who consider ingress hostnames sensitive can point
// SPAM_HOST_DOH_URL at a self-hosted DoH proxy with a public upstream,
// or set it to "off" to disable the public lookup entirely (classification
// then falls back to the pre-DoH split-horizon behaviour).
const defaultDoHURL = "https://cloudflare-dns.com/dns-query"

// wildcardProbeLabel is the deliberately-improbable label used to detect
// public wildcard records: if <label>.<parent-zone> resolves to the same
// addresses as the host itself, the host's answer is wildcard-derived
// and proves zone-level exposure, not host-level. Fixed (not random) so
// the kv cache and upstream resolver caches both hold across passes.
const wildcardProbeLabel = "spam-wc-probe-zq3x7v9k"

const (
	dohTimeout      = 5 * time.Second
	dohMaxBodyBytes = 64 << 10 // dns-json answers are tiny; cap defensively
	wildcardPrefix  = "dohwc:"
)

var (
	dohURL = loadDoHURL()
	// Timeout-only client: the zero Transport is http.DefaultTransport,
	// which honours HTTPS_PROXY et al — required in proxy-only egress
	// environments.
	dohClient = &http.Client{Timeout: dohTimeout}
)

// loadDoHURL returns the dns-json endpoint for the public lookup, or ""
// when the operator disabled it. Any endpoint speaking the dns-json GET
// dialect works (Cloudflare's /dns-query, Google's /resolve, or a
// self-hosted proxy).
func loadDoHURL() string {
	raw := strings.TrimSpace(os.Getenv("SPAM_HOST_DOH_URL"))
	switch {
	case raw == "":
		return defaultDoHURL
	case strings.EqualFold(raw, "off"), strings.EqualFold(raw, "disabled"):
		return ""
	default:
		return raw
	}
}

// Public-lookup failure modes. The distinction matters to Classify:
// "unresolvable" is an authoritative answer (the name is NOT in public
// DNS) and confirms an internal-only verdict; "unavailable" means we had
// no public vantage at all, so classification falls back to the legacy
// split-horizon path rather than trusting an absence we never observed.
const (
	publicErrUnresolvable = "unresolvable"
	publicErrUnavailable  = "unavailable"
)

// dohResponse is the subset of the dns-json answer we read. Answer
// carries the whole resolution chain (CNAMEs included); only A (type 1)
// and AAAA (type 28) records hold addresses.
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

const (
	dnsStatusNoError  = 0
	dnsStatusNXDomain = 3
	dnsTypeA          = 1
	dnsTypeAAAA       = 28
)

// dohQuery asks the DoH endpoint for one record type. Returns the
// addresses, whether the zone authoritatively denied the name
// (NXDOMAIN), and a transport/SERVFAIL error when the answer can't be
// trusted either way.
func dohQuery(ctx context.Context, host, qtype string) (ips []string, nxdomain bool, err error) {
	reqURL := dohURL + "?name=" + url.QueryEscape(host) + "&type=" + qtype
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("doh status %d", resp.StatusCode)
	}

	var body dohResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, dohMaxBodyBytes)).Decode(&body); err != nil {
		return nil, false, err
	}
	switch body.Status {
	case dnsStatusNoError:
	case dnsStatusNXDomain:
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("doh rcode %d", body.Status)
	}
	for _, a := range body.Answer {
		if a.Type == dnsTypeA || a.Type == dnsTypeAAAA {
			ips = append(ips, a.Data)
		}
	}
	return ips, false, nil
}

// resolvePublic resolves host through the public DoH vantage. errKind is
// "" on a positive answer, publicErrUnresolvable when public DNS
// authoritatively has no record, publicErrUnavailable when the lookup
// itself failed (or DoH is disabled).
func resolvePublic(ctx context.Context, host string) (ips []string, errKind string) {
	if dohURL == "" {
		return nil, publicErrUnavailable
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dohTimeout)
	defer cancel()

	ipsA, nx, err := dohQuery(lookupCtx, host, "A")
	if err != nil {
		return nil, publicErrUnavailable
	}
	if nx {
		return nil, publicErrUnresolvable
	}
	if len(ipsA) > 0 {
		return ipsA, ""
	}
	// NOERROR with no A records — the name exists (e.g. CNAME-only or
	// AAAA-only). Check AAAA before concluding it has no address.
	ipsAAAA, _, err := dohQuery(lookupCtx, host, "AAAA")
	if err != nil {
		return nil, publicErrUnavailable
	}
	if len(ipsAAAA) > 0 {
		return ipsAAAA, ""
	}
	return nil, publicErrUnresolvable
}

// publicAnswerIsWildcard reports whether host's public answer is
// wildcard-derived: a probe label under the same parent zone resolves to
// the exact same address set. A host with a dedicated record pointing at
// the same target as the wildcard is indistinguishable from DNS data
// alone and gets flagged too — Classify then falls back to the
// split-horizon answer, which is the conservative read. The probe result
// is cached per parent zone so one probe covers every host under it.
//
// Parents with a single label (TLDs) are never probed — the probe name
// would be a registrable domain, not a zone we have any business
// querying for wildcard semantics.
func publicAnswerIsWildcard(ctx context.Context, cs cache.Store, host string, hostIPs []string) bool {
	parent := strings.SplitN(host, ".", 2)
	if len(parent) != 2 || strings.Count(parent[1], ".") < 1 {
		return false
	}
	zone := parent[1]

	type probeResult struct {
		IPs []string `json:"ips"`
	}
	key := wildcardPrefix + cacheKeyHash() + ":" + zone
	probe, ok, _ := cache.GetJSON[probeResult](ctx, cs, key)
	if !ok {
		ips, errKind := resolvePublic(ctx, wildcardProbeLabel+"."+zone)
		if errKind == publicErrUnavailable {
			// No vantage to probe from — don't cache, don't flag.
			return false
		}
		probe = probeResult{IPs: ips}
		_ = cache.SetJSON(ctx, cs, key, probe, cacheTTL)
	}
	if len(probe.IPs) == 0 {
		return false
	}
	return sameIPSet(hostIPs, probe.IPs)
}

func sameIPSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, ip := range a {
		set[ip] = true
	}
	for _, ip := range b {
		if !set[ip] {
			return false
		}
	}
	return true
}
