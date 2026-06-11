// Package hostresolve owns the host_resolution table: a precomputed,
// per-host bucket (internal/external/unresolvable) that the
// /api/clusters/hosts/summary endpoint reads with a plain SQL aggregate.
// Before this package existed, the summary handler did a synchronous
// DNS lookup per unique host inline, which serialised into multi-second
// responses on real fleets — see HostSummaryHandler in
// internal/scam/handler.go. A background Worker (worker.go) periodically
// resolves every host present in host_exposure through the system
// resolver (or SPAM_HOST_DNS_RESOLVER when set) and upserts the
// classification here; the handler joins host_resolution and answers
// in O(rows-in-acl) without ever touching DNS.
//
// The resolver primitives in this file (Resolve, Classify, IsPrivateIP)
// intentionally duplicate the env-driven setup in internal/scam so the
// worker can run without dragging in the entire scam package, and so a
// future refactor that consolidates the two has a clear seam.
package hostresolve

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
)

// Result is the cached shape of one host's DNS verdict from both
// vantage points. IPs/IsLocal/Error mirror scam.resolveResult (the
// split-horizon view) so the future consolidation lands as a type alias
// rather than a rename; the Public* fields carry the DoH public-DNS
// view that drives classification under split-DNS.
type Result struct {
	Host    string   `json:"host"`
	IPs     []string `json:"ips"`
	IsLocal bool     `json:"is_local"`
	Error   string   `json:"error,omitempty"`
	// Public-DNS vantage (DoH — see doh.go). PublicError is
	// publicErrUnresolvable when public DNS authoritatively has no
	// record, publicErrUnavailable when the DoH lookup failed or is
	// disabled. Wildcard marks a public answer that matches the parent
	// zone's wildcard probe — zone-level exposure, not host-level.
	PublicIPs   []string `json:"public_ips,omitempty"`
	PublicError string   `json:"public_error,omitempty"`
	Wildcard    bool     `json:"wildcard,omitempty"`
}

// Classification buckets. Stored verbatim in host_resolution.classification
// and surfaced through the summary endpoint via a CASE/FILTER aggregate.
const (
	ClassInternal     = "internal"
	ClassExternal     = "external"
	ClassUnresolvable = "unresolvable"
	ClassPending      = "pending"
)

// cacheTTL matches scam's: DNS for operator-facing ingress hosts moves
// on the timescale of cluster reconfigs (days), not minutes, so a 24h
// in-cache lifetime keeps the resolver load minimal without making the
// summary visibly stale.
const (
	cachePrefix = "resolve:"
	cacheTTL    = 24 * time.Hour
)

var (
	resolverAddr  = loadResolverAddr()
	netResolver   = newResolver(resolverAddr)
	internalCIDRs = loadInternalCIDRs()
)

// loadResolverAddr returns the operator-configured DNS server, or "" for
// the system resolver. The system default matters: the pod's resolver
// knows split-horizon internal zones, while a hardcoded public resolver
// can never resolve internal-only hosts (and outbound :53 to the
// internet is blocked in most of our environments), which left every
// host unresolvable and the internal/external split empty.
func loadResolverAddr() string {
	raw := strings.TrimSpace(os.Getenv("SPAM_HOST_DNS_RESOLVER"))
	if raw == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	return net.JoinHostPort(raw, "53")
}

func newResolver(addr string) *net.Resolver {
	if addr == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
}

func loadInternalCIDRs() []*net.IPNet {
	raw := strings.TrimSpace(os.Getenv("SPAM_HOST_INTERNAL_CIDRS"))
	if raw == "" {
		return nil
	}
	var out []*net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			log.Printf("hostresolve: ignoring invalid SPAM_HOST_INTERNAL_CIDRS entry %q: %v", entry, err)
			continue
		}
		out = append(out, cidr)
	}
	return out
}

// IsPrivateIP returns true when ipStr falls in RFC1918, RFC4193 (IPv6
// ULA), loopback, link-local, or any operator-configured
// SPAM_HOST_INTERNAL_CIDRS range. Mirrors the equivalent in scam so the
// worker and the legacy inline-resolve path agree on classification.
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, cidr := range internalCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// cacheKeyHash digests every config knob that changes a lookup's
// outcome — resolver address, internal CIDR ranges, DoH endpoint — so a
// config change naturally invalidates cached results instead of serving
// verdicts computed under the old config.
func cacheKeyHash() string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(resolverAddr))
	_, _ = h.Write([]byte(dohURL))
	for _, cidr := range internalCIDRs {
		_, _ = h.Write([]byte(cidr.String()))
	}
	return fmt.Sprintf("%x", h.Sum64())
}

func cacheKey(host string) string {
	return cachePrefix + cacheKeyHash() + ":" + host
}

// allPrivate reports whether every address is private. False for an
// empty slice — no addresses proves nothing. Answer order is
// nondeterministic (round-robin, mixed A/AAAA), and any single public
// address means the host is reachable from outside.
func allPrivate(ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !IsPrivateIP(ip) {
			return false
		}
	}
	return true
}

// Resolve does (or replays from cache) the two DNS lookups for a host:
// the split-horizon view through the pod's/operator's resolver, and the
// public view through DoH. Negative results are cached too, so an
// unresolvable host doesn't pay the lookup timeouts every pass.
func Resolve(ctx context.Context, cs cache.Store, host string) Result {
	key := cacheKey(host)
	if cached, ok, _ := cache.GetJSON[Result](ctx, cs, key); ok {
		return cached
	}

	res := Result{Host: host}

	// Split-horizon view. Kept even when it fails — the public lookup
	// below may still classify the host.
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	ips, err := netResolver.LookupHost(lookupCtx, host)
	cancel()
	if err != nil {
		res.Error = "unresolvable"
	} else {
		res.IPs = ips
		res.IsLocal = allPrivate(ips)
	}

	// Public view. A positive answer is checked against the parent
	// zone's wildcard probe so a *.zone record doesn't masquerade as a
	// host-specific public record.
	res.PublicIPs, res.PublicError = resolvePublic(ctx, host)
	if len(res.PublicIPs) > 0 {
		res.Wildcard = publicAnswerIsWildcard(ctx, cs, host, res.PublicIPs)
	}

	// A transient DoH outage shouldn't pin a vantage-less verdict for
	// the full TTL — cache it briefly so the next worker pass retries
	// the public lookup.
	ttl := cacheTTL
	if res.PublicError == publicErrUnavailable {
		ttl = time.Hour
	}
	_ = cache.SetJSON(ctx, cs, key, res, ttl)
	return res
}

// Classify reduces the two-vantage DNS result plus the cluster-reported
// LB IP CSV to a single classification bucket:
//
//  1. A host-specific public DNS answer wins. Under split-DNS the
//     internal resolver answers with the internal zone record, so only
//     the public vantage can prove external exposure — a public record
//     pointing at a public address is external no matter what the
//     internal zone says.
//  2. A wildcard-derived public answer proves the *zone* resolves, not
//     the host, so the split-horizon answer is preferred when there is
//     one; a host unknown even internally falls back to the wildcard
//     target addresses.
//  3. No public answer (absent from public DNS, or DoH unavailable):
//     the legacy path — split-horizon answer first, then the first LB
//     IP, then unresolvable/pending.
func Classify(res Result, lbIPsCSV string) string {
	if len(res.PublicIPs) > 0 && !res.Wildcard {
		if allPrivate(res.PublicIPs) {
			return ClassInternal
		}
		return ClassExternal
	}
	if res.Wildcard {
		if res.Error == "" && len(res.IPs) > 0 {
			if res.IsLocal {
				return ClassInternal
			}
			return ClassExternal
		}
		if allPrivate(res.PublicIPs) {
			return ClassInternal
		}
		return ClassExternal
	}
	if res.Error == "" && len(res.IPs) > 0 {
		if res.IsLocal {
			return ClassInternal
		}
		return ClassExternal
	}
	if first := strings.TrimSpace(strings.SplitN(lbIPsCSV, ",", 2)[0]); first != "" {
		if IsPrivateIP(first) {
			return ClassInternal
		}
		return ClassExternal
	}
	if res.Error != "" {
		return ClassUnresolvable
	}
	return ClassPending
}
