# TenantShield: My Secure SDLC Project

This is a small Go API project I made to learn more about API security. I started with a purposely vulnerable version, used local fake data to show the problems, and then tried to fix the issues with JWTs, roles, input validation, logging, and tests.

I used fake tenants and users only. The vulnerable branch is for local learning and should not be deployed.

Disclaimer: This project had AI-assistance for:
- initial Go code generation
- Test-case and CI workflow drafting
- Code-review suggestions and debugging assistance
  
## What I worked on

- Week 1: I made a basic multi-tenant API with two intentional security problems.
- Week 2: I used Burp Suite locally to change requests and noted what happened.
- Week 3: I added JWT checks and tried to make sure a user can only access their own tenant's data.
- Week 4: I added safer update inputs, audit logging, tests, and a GitHub Actions workflow.

## How local setup works

```text
Browser or curl -> Burp Suite on port 8080 -> Go API on port 8081 -> fake in-memory data
```

For protected requests, the API checks the JWT first. It then gets the tenant and role from the token instead of trusting a value from the URL.

## Run it locally

You need Go 1.22 or newer. Set local-only values first. DO NOT commit these values to GitHub.

```bash
export TENANTSHIELD_JWT_SECRET='replace-this-with-a-long-secret-at-least-32-characters'
export TENANTSHIELD_DEMO_PASSWORD='demo-password-123'
go run .
```

To get a short-lived demo token, use this:

```bash
curl -sS -X POST http://127.0.0.1:8081/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@acme.test","password":"demo-password-123"}'
```

Copy the `access_token` from the response and save it in a shell variable:

```bash
TOKEN='paste-the-access-token-here'
```

Then use the token in a request:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8081/api/v1/projects?tenant_id=13'
```

Even though the URL says tenant 13, an Alice token should only return tenant 12 projects. That was the main BOLA fix I wanted to test.

## Demo users and routes

The two local demo users are:

| Email | Tenant | Role |
| --- | --- | --- |
| `alice@acme.test` | 12 | `employee` |
| `bob@globex.test` | 13 | `super_admin` |

Both use the password stored in `TENANTSHIELD_DEMO_PASSWORD`.

| Method | Route | What it does |
| --- | --- | --- |
| `GET` | `/healthz` | Simple server health check; no token needed |
| `POST` | `/api/v1/auth/login` | Creates a local demo JWT |
| `GET` | `/api/v1/projects` | Returns projects for the tenant in the JWT |
| `PUT` | `/api/v1/users/{id}` | Lets a user update their own `first_name` or `bio` |
| `GET` | `/api/v1/admin/users` | Shows users in the admin's tenant; requires `super_admin` |

For example, this is a safe profile update request:

```bash
curl -X PUT http://127.0.0.1:8081/api/v1/users/5 \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"first_name":"Alicia","bio":"Learning API security"}'
```

## Run the checks

Before opening a pull request, I run:

```bash
gofmt -w main.go main_test.go middleware/*.go dto/*.go logger/*.go
go vet ./...
go test -race ./...
```

The GitHub Actions workflow also runs formatting, tests, `go vet`, and `gosec` on pushes and pull requests.

## What changed after hardening

| Test | Vulnerable version | Hardened version |
| --- | --- | --- |
| Change `tenant_id` in the URL | Could potentially view another tenant's projects | The URL value is ignored and token's tenant is used |
| No token or bad token | No real protection | `401 Unauthorized` |
| Employee opens admin route | No role check | `403 Forbidden` |
| Send `role: super_admin` while updating a profile | Role could be changed | Request gets `400 Bad Request` |
| Try to update a different tenant's user | Not protected | `403 Forbidden` |

## Notes and documents

- [My Week 2 findings](docs/week-2-vulnerability-reports.md)
- [What I added in Weeks 3 and 4](docs/week-3-4-security-design.md)
- [GitHub Actions checks](.github/workflows/ci.yml)

## Things I would improve later

This is still a learning project. The login route is only there so I can create local test tokens. In a real app, I would use a real identity provider, a maintained JWT package, key rotation, a database, and a proper secret manager.
