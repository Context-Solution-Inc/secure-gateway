package authservice

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lley154/secure-gateway/internal/ratelimit"
)

// rateLimiters holds the auth service's in-process abuse controls (PRD §10.2):
// a per-IP limiter on sensitive endpoints and a per-account limiter on auth
// attempts. Both are nil when rate limiting is disabled.
type rateLimiters struct {
	ip         *ratelimit.KeyedLimiter
	account    *ratelimit.KeyedLimiter
	trustProxy bool
}

func newRateLimiters(cfg ServerConfig) *rateLimiters {
	if !cfg.RateLimitEnabled {
		return &rateLimiters{trustProxy: cfg.TrustProxy}
	}
	return &rateLimiters{
		ip:         ratelimit.NewKeyedLimiter(float64(cfg.RateLimitIPPerMin), cfg.RateLimitIPBurst),
		account:    ratelimit.NewKeyedLimiter(float64(cfg.RateLimitAccountPerMin), cfg.RateLimitAccountBurst),
		trustProxy: cfg.TrustProxy,
	}
}

// sweep reclaims idle limiter entries until ctx is canceled.
func (rl *rateLimiters) sweep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rl.ip.Sweep(10 * time.Minute)
			rl.account.Sweep(10 * time.Minute)
		}
	}
}

// limit wraps a sensitive handler with per-IP and (when derivable) per-account
// rate limiting. Over-limit requests get HTTP 429 + Retry-After before the
// handler runs. The account is read from the bearer secret's prefix
// (account_id.<rand>); refresh/pairing requests without an account bearer fall
// back to IP-only limiting.
func (s *Server) limit(next http.HandlerFunc) http.HandlerFunc {
	rl := s.rl
	return func(w http.ResponseWriter, r *http.Request) {
		if rl.ip != nil {
			ip := clientIP(r, rl.trustProxy)
			if !rl.ip.Allow(ip) {
				s.tooManyRequests(w, "ip")
				return
			}
			if acct := accountFromBearer(r); acct != "" && !rl.account.Allow(acct) {
				s.tooManyRequests(w, "account")
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) tooManyRequests(w http.ResponseWriter, kind string) {
	if s.svc.metrics != nil {
		s.svc.metrics.RateLimited.WithLabelValues(kind).Inc()
	}
	w.Header().Set("Retry-After", "1")
	writeErr(w, http.StatusTooManyRequests, "rate_limited")
}

// accountFromBearer extracts the account id encoded as the prefix of the bearer
// secret (account_id.<rand>), or "" when there is no account bearer.
func accountFromBearer(r *http.Request) string {
	secret := bearer(r)
	if secret == "" {
		return ""
	}
	acct, _, ok := strings.Cut(secret, ".")
	if !ok {
		return ""
	}
	return acct
}

// clientIP resolves the client's IP. With trustProxy it honors the first hop of
// X-Forwarded-For (from a trusted fronting proxy); otherwise the socket address.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
