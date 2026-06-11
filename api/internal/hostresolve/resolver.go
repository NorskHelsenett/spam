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

// Result is the cached shape of a single DNS lookup. Mirrors
// scam.resolveResult on purpose so the future consolidation lands as a
// type alias rather than a rename.
type Result struct {
	Host    string   `json:"host"`
	IPs     []string `json:"ips"`
	IsLocal bool     `json:"is_local"`
	Error   string   `json:"error,omitempty"`
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

func cacheKey(host string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(resolverAddr))
	for _, cidr := range internalCIDRs {
		_, _ = h.Write([]byte(cidr.String()))
	}
	return fmt.Sprintf("%s%x:%s", cachePrefix, h.Sum64(), host)
}

// Resolve does (or replays from cache) a single DNS lookup. Negative
// results are cached too, so an unresolvable host doesn't pay the 3s
// lookup timeout every pass.
func Resolve(ctx context.Context, cs cache.Store, host string) Result {
	key := cacheKey(host)
	if cached, ok, _ := cache.GetJSON[Result](ctx, cs, key); ok {
		return cached
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ips, err := netResolver.LookupHost(lookupCtx, host)
	if err != nil {
		res := Result{Host: host, Error: "unresolvable"}
		_ = cache.SetJSON(ctx, cs, key, res, cacheTTL)
		return res
	}

	// Internal iff every resolved address is private: answer order is
	// nondeterministic (round-robin, mixed A/AAAA), and any public
	// address means the host is reachable from outside.
	local := len(ips) > 0
	for _, ip := range ips {
		if !IsPrivateIP(ip) {
			local = false
			break
		}
	}
	res := Result{Host: host, IPs: ips, IsLocal: local}
	_ = cache.SetJSON(ctx, cs, key, res, cacheTTL)
	return res
}

// Classify reduces a DNS result plus the cluster-reported LB IP CSV to
// a single classification bucket. Mirrors classifyHostInto in scam:
//
//   1. DNS A record wins — split-horizon/public DNS may point a host
//      at an external address even when the cluster's LB is private.
//   2. DNS missing → fall back to the first LB IP.
//   3. Neither → unresolvable when DNS errored, pending when the host
//      simply has nothing yet (caller passes Result{} to signal "I
//      haven't even tried to resolve this one").
func Classify(res Result, lbIPsCSV string) string {
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
