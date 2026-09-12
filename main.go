package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	"tenantshield/dto"
	"tenantshield/logger"
	"tenantshield/middleware"
)

type User struct {
	ID        int    `json:"id"`
	TenantID  int    `json:"tenant_id"`
	FirstName string `json:"first_name"`
	Bio       string `json:"bio"`
	Role      string `json:"role"`
}
type Project struct {
	ID          int    `json:"id"`
	TenantID    int    `json:"tenant_id"`
	Name        string `json:"name"`
	Sensitivity string `json:"sensitivity"`
}

type store struct {
	mu       sync.RWMutex
	users    map[int]User
	projects map[int][]Project
}

func newStore() *store {
	return &store{users: map[int]User{5: {5, 12, "Alice", "Security Analyst", "employee"}, 6: {6, 13, "Bob", "DevOps Engineer", "super_admin"}}, projects: map[int][]Project{12: {{101, 12, "Acme Quarter 3 Financials", "Confidential"}}, 13: {{202, 13, "Globex Merger Strategy", "Top Secret"}}}}
}
func (s *store) projectsForTenant(t int) []Project {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Project(nil), s.projects[t]...)
}
func (s *store) user(id int) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}
func (s *store) usersForTenant(t int) []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []User{}
	for _, u := range s.users {
		if u.TenantID == t {
			out = append(out, u)
		}
	}
	return out
}
func (s *store) updateProfile(id int, in dto.UserUpdateDTO) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return User{}, false
	}
	if in.FirstName != nil {
		u.FirstName = *in.FirstName
	}
	if in.Bio != nil {
		u.Bio = *in.Bio
	}
	s.users[id] = u
	return u, true
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var demoIdentities = map[string]middleware.Claims{"alice@acme.test": {UserID: 5, TenantID: 12, Role: "employee"}, "bob@globex.test": {UserID: 6, TenantID: 13, Role: "super_admin"}}

func main() {
	secret := []byte(os.Getenv("TENANTSHIELD_JWT_SECRET"))
	if len(secret) < 32 {
		log.Fatal("TENANTSHIELD_JWT_SECRET must contain at least 32 characters")
	}
	password := os.Getenv("TENANTSHIELD_DEMO_PASSWORD")
	if len(password) < 12 {
		log.Fatal("TENANTSHIELD_DEMO_PASSWORD must contain at least 12 characters")
	}
	address := os.Getenv("TENANTSHIELD_ADDR")
	if address == "" {
		address = "127.0.0.1:8081"
	}
	fmt.Printf("TenantShield hardened API listening on http://%s\n", address)
	log.Fatal(http.ListenAndServe(address, newServer(secret, password, logger.NewAuditLogger(os.Stdout))))
}

func newServer(secret []byte, password string, audit *logger.AuditLogger) http.Handler {
	data := newStore()
	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/auth/login", loginHandler(secret, password, audit))
	auth := middleware.Authenticate(secret, audit)
	mux.Handle("GET /api/v1/projects", auth(http.HandlerFunc(projectsHandler(data))))
	mux.Handle("PUT /api/v1/users/{id}", auth(middleware.RequireSelfOrRole("super_admin", audit)(http.HandlerFunc(updateUserHandler(data)))))
	mux.Handle("GET /api/v1/admin/users", auth(middleware.RequireRole("super_admin", audit)(http.HandlerFunc(adminUsersHandler(data)))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

func loginHandler(secret []byte, password string, audit *logger.AuditLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in loginRequest
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if err := d.Decode(&in); err != nil {
			audit.LogAuthenticationFailure(r, "invalid login request")
			http.Error(w, "invalid credentials", 401)
			return
		}
		claims, ok := demoIdentities[in.Email]
		if !ok || !middleware.SecureEqual(in.Password, password) {
			audit.LogAuthenticationFailure(r, "invalid credentials")
			http.Error(w, "invalid credentials", 401)
			return
		}
		token, err := middleware.IssueToken(secret, claims)
		if err != nil {
			http.Error(w, "unable to issue token", 500)
			return
		}
		writeJSON(w, 200, map[string]string{"access_token": token, "token_type": "Bearer"})
	})
}
func projectsHandler(data *store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, _ := middleware.ClaimsFromContext(r.Context())
		writeJSON(w, 200, data.projectsForTenant(claims.TenantID))
	}
}
func updateUserHandler(data *store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id <= 0 {
			http.Error(w, "invalid user ID", 400)
			return
		}
		claims, _ := middleware.ClaimsFromContext(r.Context())
		target, ok := data.user(id)
		if !ok {
			http.Error(w, "user not found", 404)
			return
		}
		if target.TenantID != claims.TenantID {
			http.Error(w, "forbidden", 403)
			return
		}
		var in dto.UserUpdateDTO
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if err := d.Decode(&in); err != nil || !errors.Is(d.Decode(&struct{}{}), io.EOF) {
			http.Error(w, "invalid update payload", 400)
			return
		}
		if err := in.Validate(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		updated, _ := data.updateProfile(id, in)
		writeJSON(w, 200, map[string]any{"message": "user profile updated", "updated_user": updated})
	}
}
func adminUsersHandler(data *store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, _ := middleware.ClaimsFromContext(r.Context())
		writeJSON(w, 200, data.usersForTenant(claims.TenantID))
	}
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("response encoding failure: %v", err)
	}
}
