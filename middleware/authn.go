package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"tenantshield/logger"
)

type contextKey struct{}
type Claims struct {
	UserID   int    `json:"user_id"`
	TenantID int    `json:"tenant_id"`
	Role     string `json:"role"`
	Expires  int64  `json:"exp"`
}

func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(contextKey{}).(Claims)
	return c, ok
}
func SecureEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func Authenticate(secret []byte, audit *logger.AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				audit.LogAuthenticationFailure(r, "missing bearer token")
				http.Error(w, "unauthorized", 401)
				return
			}
			claims, err := parseToken(secret, strings.TrimPrefix(h, "Bearer "))
			if err != nil {
				audit.LogAuthenticationFailure(r, "invalid bearer token")
				http.Error(w, "unauthorized", 401)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, claims)))
		})
	}
}

func IssueToken(secret []byte, c Claims) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("JWT secret must contain at least 32 bytes")
	}
	if c.UserID <= 0 || c.TenantID <= 0 || c.Role == "" {
		return "", errors.New("incomplete claims")
	}
	c.Expires = time.Now().Add(15 * time.Minute).Unix()
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	a := base64.RawURLEncoding.EncodeToString(header)
	b := base64.RawURLEncoding.EncodeToString(payload)
	input := a + "." + b
	return input + "." + signature(secret, input), nil
}
func parseToken(secret []byte, t string) (Claims, error) {
	p := strings.Split(t, ".")
	if len(p) != 3 {
		return Claims{}, errors.New("malformed token")
	}
	h, err := base64.RawURLEncoding.DecodeString(p[0])
	if err != nil {
		return Claims{}, errors.New("invalid header")
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	if json.Unmarshal(h, &header) != nil || header.Algorithm != "HS256" {
		return Claims{}, errors.New("unsupported algorithm")
	}
	if !SecureEqual(p[2], signature(secret, p[0]+"."+p[1])) {
		return Claims{}, errors.New("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		return Claims{}, errors.New("invalid payload")
	}
	var c Claims
	if json.Unmarshal(payload, &c) != nil || c.UserID <= 0 || c.TenantID <= 0 || c.Role == "" || c.Expires <= time.Now().Unix() {
		return Claims{}, errors.New("expired or incomplete claims")
	}
	return c, nil
}
func signature(secret []byte, input string) string {
	m := hmac.New(sha256.New, secret)
	_, _ = m.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
