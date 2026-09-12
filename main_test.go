package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tenantshield/logger"
	"tenantshield/middleware"
)

var testSecret = []byte("tenantshield-test-secret-must-be-32-bytes")

func token(t *testing.T, userID, tenantID int, role string) string {
	t.Helper()
	value, err := middleware.IssueToken(testSecret, middleware.Claims{UserID: userID, TenantID: tenantID, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func request(method, path, body, token string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}
func testServer(logs *bytes.Buffer) http.Handler {
	return newServer(testSecret, "demo-password-123", logger.NewAuditLogger(logs))
}

func TestProjectsAreTenantScoped(t *testing.T) {
	var logs bytes.Buffer
	server := testServer(&logs)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, request("GET", "/api/v1/projects?tenant_id=13", "", token(t, 5, 12, "employee")))
	if w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "Globex") || !strings.Contains(w.Body.String(), "Acme") {
		t.Fatalf("cross-tenant data leaked: %s", w.Body.String())
	}
}
func TestMissingTokenIsUnauthorized(t *testing.T) {
	var logs bytes.Buffer
	server := testServer(&logs)
	w := httptest.NewRecorder()
	r := request("GET", "/api/v1/projects", "", "")
	r.Header.Set("Authorization", "Bearer do-not-log-this-token")
	server.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("got %d", w.Code)
	}
	if strings.Contains(logs.String(), "do-not-log-this-token") {
		t.Fatal("audit log leaked bearer token")
	}
}
func TestRoleInjectionIsRejectedAndDoesNotMutate(t *testing.T) {
	var logs bytes.Buffer
	server := testServer(&logs)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, request("PUT", "/api/v1/users/5", `{"role":"super_admin"}`, token(t, 5, 12, "employee")))
	if w.Code != 400 {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	server.ServeHTTP(w, request("GET", "/api/v1/admin/users", "", token(t, 5, 12, "employee")))
	if w.Code != 403 {
		t.Fatalf("role changed or authorization failed unexpectedly: %d", w.Code)
	}
}
func TestCrossTenantProfileUpdateForbidden(t *testing.T) {
	var logs bytes.Buffer
	server := testServer(&logs)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, request("PUT", "/api/v1/users/6", `{"bio":"attempt"}`, token(t, 6, 12, "super_admin")))
	if w.Code != 403 {
		t.Fatalf("got %d", w.Code)
	}
}
func TestStrictDTOAllowsProfileFields(t *testing.T) {
	var logs bytes.Buffer
	server := testServer(&logs)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, request("PUT", "/api/v1/users/5", `{"first_name":"Alicia","bio":"Updated"}`, token(t, 5, 12, "employee")))
	if w.Code != 200 {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(response["updated_user"]), "Alicia") {
		t.Fatal("safe update was not persisted")
	}
}
