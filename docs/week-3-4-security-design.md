# Weeks 3 and 4: My Security Changes

These are the main things I added after finding the two problems in Week 2. I am still learning cybersecurity, so I kept the project small and tried to focus on understanding each layer.

## The request flow now

```text
Request comes in
  -> check JWT signature and expiration
  -> get user ID, tenant ID, and role from the token
  -> check if the user is allowed to do this action
  -> check the input fields
  -> use the tenant ID from the token when reading data
```

If the token is missing, expired, or changed, the API returns `401 Unauthorized`. If the user is logged in but does not have permission, it returns `403 Forbidden`.

## JWT authentication

I added code that checks the JWT signature and the expiration time. If it is valid, the user ID, tenant ID, and role are saved in the request context. I used these values in the later checks instead of using a tenant ID from a query parameter.

For this project, there is a basic development login endpoint that makes local test tokens. This is only to make the demo easy to run. It is not how I would build login in a real application.

## Tenant checks and roles

The projects endpoint only uses the tenant ID from the verified token. An employee can update their own profile. A `super_admin` is allowed to use the admin users endpoint, but the app still checks the tenant before letting someone update a profile.

This helped me practice a few ideas:

- **Least privilege:** do not give every user admin access.
- **Defense in depth:** use JWT checks, role checks, tenant checks, and DTO validation together.
- **Fail safely:** return an error when something is missing or not allowed.

## Safer profile updates

Before, the API decoded JSON directly into the full user model. I made a `UserUpdateDTO` that only includes `first_name` and `bio`.

If somebody sends `role`, `tenant_id`, or another unknown property, the request is rejected with `400 Bad Request`. This was my fix for the mass-assignment issue.

## Audit logging

I added JSON audit events for login and authorization failures. The logs include basic details like the time, route, status code, and user claims when they are available.

I made sure the logger does not write the Authorization header, JWT, password, cookies, or full request body. I learned that logging helpful information is important, but logging secrets can create a separate security problem.

## Tests and CI

I added tests for:

- changing the tenant ID in the URL;
- missing or changed tokens;
- trying to inject `role: super_admin`;
- trying to update a user in another tenant; and
- a normal profile update.

The GitHub Actions workflow runs formatting, `go vet`, unit tests, and `gosec`. I used this so future changes have basic checks before merging.

## What I would do differently in a real project

I would not use the demo login endpoint or keep a shared demo password. I would use an identity provider, a database that enforces tenant filtering, a secret manager, and a maintained JWT library. I would also have another person review the authorization rules, because authorization bugs are easy to miss.
