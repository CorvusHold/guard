package ratelimit

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/labstack/echo/v4"
    metrics "github.com/corvusHold/guard/internal/metrics"
)

// Policy defines a simple fixed-window rate limit.
// Limit requests within Window per derived key.
type Policy struct {
    // Name is a short identifier for the limited endpoint, used for logging/metrics (e.g. "auth:login").
    Name   string
    Window time.Duration
    Limit  int
    // Optional dynamic resolvers (if provided, override Window/Limit per request)
    WindowFunc func(echo.Context) time.Duration
    LimitFunc  func(echo.Context) int
    // Key builds the bucket key for this request.
    // Example: func(c echo.Context) string { return "login:" + c.RealIP() }
    Key func(echo.Context) string
}

// Store abstracts a shared counter store (e.g., Redis) for fixed-window limiting.
type Store interface {
    // Allow increments the counter for the key in the given window and returns whether the request is allowed.
    // If not allowed, retryAfterSec indicates seconds until the window resets.
    Allow(ctx echo.Context, key string, limit int, window time.Duration) (allowed bool, retryAfterSec int, err error)
}

// Middleware returns an Echo middleware enforcing the provided Policy using an in-memory fixed window.
// Note: This is process-local. For multi-instance deployments, prefer a shared store (e.g., Redis).
func Middleware(p Policy) echo.MiddlewareFunc {
    if p.Window <= 0 {
        p.Window = time.Minute
    }
    if p.Limit <= 0 {
        p.Limit = 60
    }
    // simple in-memory store
    type bucket struct {
        start time.Time
        count int
    }
    var (
        mu      sync.Mutex
        buckets = make(map[string]*bucket)
    )

    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            key := "global"
            if p.Key != nil {
                key = p.Key(c)
            }
            // compute effective window/limit
            win := p.Window
            lim := p.Limit
            if p.WindowFunc != nil { if w := p.WindowFunc(c); w > 0 { win = w } }
            if p.LimitFunc != nil { if l := p.LimitFunc(c); l > 0 { lim = l } }

            now := time.Now()
            var retryAfter int
            mu.Lock()
            b, ok := buckets[key]
            if !ok || now.Sub(b.start) >= win {
                // reset window
                buckets[key] = &bucket{start: now, count: 1}
                mu.Unlock()
                return next(c)
            }
            if b.count < lim {
                b.count++
                mu.Unlock()
                return next(c)
            }
            // over limit
            retryAfter = int(win - now.Sub(b.start)) / int(time.Second)
            mu.Unlock()
            // metrics and logging for observability
            src := "ip"
            if strings.Contains(key, ":ten:") { src = "tenant" }
            metrics.IncRateLimitExceeded(p.Name, src)
            c.Logger().Warnf("rate limit exceeded: endpoint=%s key=%s limit=%d window=%s retry_after=%ds", p.Name, key, lim, win.String(), retryAfter)
            c.Response().Header().Set("Retry-After", strconvItoa(retryAfter))
            return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
        }
    }
}

// MiddlewareWithStore uses a shared Store (e.g., Redis) for distributed rate limiting.
func MiddlewareWithStore(p Policy, s Store) echo.MiddlewareFunc {
    if p.Window <= 0 {
        p.Window = time.Minute
    }
    if p.Limit <= 0 {
        p.Limit = 60
    }
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            key := "global"
            if p.Key != nil { key = p.Key(c) }
            win := p.Window
            lim := p.Limit
            if p.WindowFunc != nil { if w := p.WindowFunc(c); w > 0 { win = w } }
            if p.LimitFunc != nil { if l := p.LimitFunc(c); l > 0 { lim = l } }
            allowed, retryAfter, err := s.Allow(c, key, lim, win)
            if err == nil && allowed {
                return next(c)
            }
            if err != nil {
                // Fail-open on store errors
                return next(c)
            }
            // blocked: record metrics/log and set header
            src := "ip"
            if strings.Contains(key, ":ten:") { src = "tenant" }
            metrics.IncRateLimitExceeded(p.Name, src)
            c.Logger().Warnf("rate limit exceeded: endpoint=%s key=%s limit=%d window=%s retry_after=%ds", p.Name, key, lim, win.String(), retryAfter)
            if retryAfter > 0 {
                c.Response().Header().Set("Retry-After", strconvItoa(retryAfter))
            }
            return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
        }
    }
}

// KeyTenantOrIP attempts to extract a tenant identifier from query (?tenant_id) or JSON body {"tenant_id": "..."}.
// Falls back to the request's real IP. Prefix allows per-endpoint separation.
func KeyTenantOrIP(prefix string) func(echo.Context) string {
    return func(c echo.Context) string {
        ten := c.QueryParam("tenant_id")
        if ten == "" && strings.Contains(strings.ToLower(c.Request().Header.Get("Content-Type")), "application/json") {
            // Non-destructively peek request body for tenant_id
            if c.Request().Body != nil {
                // Read and restore
                buf, _ := io.ReadAll(c.Request().Body)
                c.Request().Body = io.NopCloser(bytes.NewReader(buf))
                var tmp struct{ TenantID string `json:"tenant_id"` }
                // Best-effort parse
                _ = json.Unmarshal(buf, &tmp)
                if tmp.TenantID != "" {
                    ten = tmp.TenantID
                }
            }
        }
        if ten == "" {
            return prefix + ":ip:" + c.RealIP()
        }
        return prefix + ":ten:" + ten
    }
}

// small helper to avoid importing strconv everywhere here
func strconvItoa(i int) string {
    // fast path for small ints
    return string(intToBytes(i))
}

func intToBytes(i int) []byte {
    if i == 0 {
        return []byte{'0'}
    }
    neg := false
    if i < 0 {
        neg = true
        i = -i
    }
    var b [20]byte
    bp := len(b)
    for i > 0 {
        bp--
        b[bp] = byte('0' + i%10)
        i /= 10
    }
    if neg {
        bp--
        b[bp] = '-'
    }
    return b[bp:]
}
