package middleware

import (
	"fmt"
	"net/http"
	"tenantshield/logger"
)

func RequireRole(required string, audit *logger.AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := ClaimsFromContext(r.Context())
			if !ok || c.Role != required {
				audit.LogAuthorizationFailure(r, c.UserID, c.TenantID, c.Role, required)
				http.Error(w, "forbidden", 403)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
func RequireSelfOrRole(required string, audit *logger.AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := ClaimsFromContext(r.Context())
			if !ok || (r.PathValue("id") != fmt.Sprintf("%d", c.UserID) && c.Role != required) {
				audit.LogAuthorizationFailure(r, c.UserID, c.TenantID, c.Role, "self or "+required)
				http.Error(w, "forbidden", 403)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
