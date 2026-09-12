package logger

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// AuditLogger never records headers, credentials, bearer tokens, cookies, or bodies.
type AuditLogger struct {
	writer io.Writer
	mu     sync.Mutex
}

func NewAuditLogger(w io.Writer) *AuditLogger { return &AuditLogger{writer: w} }

type event struct {
	Timestamp      time.Time `json:"timestamp"`
	EventType      string    `json:"event_type"`
	RequestID      string    `json:"request_id,omitempty"`
	ClientIP       string    `json:"client_ip"`
	Actor          actor     `json:"actor,omitempty"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	RequiredRole   string    `json:"required_role,omitempty"`
	StatusCode     int       `json:"status_code"`
	Reason         string    `json:"reason,omitempty"`
	RedactionFlags flags     `json:"redaction_flags"`
}
type actor struct {
	UserID   int    `json:"user_id,omitempty"`
	TenantID int    `json:"tenant_id,omitempty"`
	Role     string `json:"role,omitempty"`
}
type flags struct {
	AuthHeaderStripped bool `json:"auth_header_stripped"`
	PayloadRedacted    bool `json:"payload_redacted"`
}

func (a *AuditLogger) LogAuthenticationFailure(r *http.Request, reason string) {
	a.write(event{time.Now().UTC(), "AUTHENTICATION_FAILURE", r.Header.Get("X-Request-ID"), clientIP(r), actor{}, r.Method, r.URL.Path, "", 401, reason, flags{true, true}})
}
func (a *AuditLogger) LogAuthorizationFailure(r *http.Request, userID, tenantID int, role, required string) {
	a.write(event{time.Now().UTC(), "AUTHORIZATION_FAILURE", r.Header.Get("X-Request-ID"), clientIP(r), actor{userID, tenantID, role}, r.Method, r.URL.Path, required, 403, "", flags{true, true}})
}
func (a *AuditLogger) write(e event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = json.NewEncoder(a.writer).Encode(e)
}
func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return h
	}
	return r.RemoteAddr
}
