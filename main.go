package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// ============================================================================
// DATA MODELS (Database Entities)
// ============================================================================

type User struct {
	ID        int    `json:"id"`
	TenantID  int    `json:"tenant_id"`
	FirstName string `json:"first_name"`
	Bio       string `json:"bio"`
	Role      string `json:"role"` // "employee" or "super_admin"
}

type Project struct {
	ID          int    `json:"id"`
	TenantID    int    `json:"tenant_id"`
	Name        string `json:"name"`
	Sensitivity string `json:"sensitivity"`
}

// ============================================================================
// IN-MEMORY MOCK DATABASE
// ============================================================================

var usersDB = map[int]User{
	5: {ID: 5, TenantID: 12, FirstName: "Alice", Bio: "Security Analyst", Role: "employee"},
	6: {ID: 6, TenantID: 13, FirstName: "Bob", Bio: "DevOps Engineer", Role: "super_admin"},
}

var projectsDB = map[int][]Project{
	12: {
		{ID: 101, TenantID: 12, Name: "Acme Quarter 3 Financials", Sensitivity: "Confidential"},
	},
	13: {
		{ID: 202, TenantID: 13, Name: "Globex Merger Strategy", Sensitivity: "Top Secret"},
	},
}

// ============================================================================
// API HANDLERS (Phase 1: Unhardened Baseline)
// ============================================================================

// 1. Mock Login Endpoint
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Mock login successful",
		"note":    "In Phase 1, auth headers are unverified mock tokens.",
	})
}

// 2. Fetch Projects (VULNERABLE TO BOLA / OWASP API1:2023)
// Flaw: Backend trusts client-supplied query parameter 'tenant_id' without verifying identity.
func getProjectsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read parameter directly from URL query string
	tenantIDStr := r.URL.Query().Get("tenant_id")
	if tenantIDStr == "" {
		http.Error(w, "Missing tenant_id parameter", http.StatusBadRequest)
		return
	}

	tenantID, err := strconv.Atoi(tenantIDStr)
	if err != nil {
		http.Error(w, "Invalid tenant_id", http.StatusBadRequest)
		return
	}

	// Fetch projects directly for requested tenant_id (No tenancy verification!)
	projects, exists := projectsDB[tenantID]
	if !exists {
		projects = []Project{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

// 3. Update User Profile (VULNERABLE TO MASS ASSIGNMENT / BOPLA / OWASP API3:2023)
// Flaw: Unmarshals request JSON body directly into User database struct without field filtering.
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract User ID from URL path (e.g., /api/v1/users/5)
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		http.Error(w, "Invalid user URL path", http.StatusBadRequest)
		return
	}

	userID, err := strconv.Atoi(pathParts[4])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	existingUser, exists := usersDB[userID]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Directly unmarshal incoming JSON payload into existingUser struct
	// Threat: Attacker can supply "role": "super_admin" in JSON to overwrite account role!
	if err := json.NewDecoder(r.Body).Decode(&existingUser); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Save modified struct back to mock database
	usersDB[userID] = existingUser

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "User profile updated successfully",
		"updated_user": existingUser,
	})
}

// ============================================================================
// MAIN SERVER ROUTER
// ============================================================================

func main() {
	http.HandleFunc("/api/v1/auth/login", loginHandler)
	http.HandleFunc("/api/v1/projects", getProjectsHandler)
	http.HandleFunc("/api/v1/users/", updateUserHandler)

	fmt.Println("=======================================================")
	fmt.Println(" TenantShield Unhardened API Server Listening")
	fmt.Println(" URL: http://127.0.0.1:8081")
	fmt.Println(" Environment: WSL2 / Development")
	fmt.Println("=======================================================")

	// Bind only to loopback. Burp Suite can listen on 127.0.0.1:8080 and
	// forward requests to this local development server on port 8081.
	if err := http.ListenAndServe("127.0.0.1:8081", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
