# Repository Guidelines

## Repository Scope

This is the independent Go repository `github.com/DWCarrot/caddy-basic-auth-ext`, also used as a Git submodule of homelab-gateway. Run the commands below from this repository's root. Keep changes and commits in this repository; updating a consuming repository's submodule pointer is a separate change. Standalone development does not require the parent gateway or its other plugins.

## Project Structure

- `basicauthext.go` registers the Caddy authentication provider and implements credential checks, permission checks, and the password comparison cache.
- `authstorage.go` parses account files and manages the shared account cache.
- `caddyfile.go` registers and parses the `basic_auth_ext` directive.
- `authstorage_test.go` contains account parsing tests; keep new `*_test.go` files beside the implementation.
- `Caddyfile.demo`, `accounts-demo.txt`, and `README.md` describe the local authentication demo.

## Build and Development

Use Go 1.23.5 or newer. `go.mod` currently pins Caddy v2.9.1.

- `go mod download`: download module dependencies.
- `go build ./...`: compile the Go packages.
- `go test ./...`: run all tests.
- `go vet ./...`: run static checks.
- With xcaddy installed, `xcaddy build v2.9.1 --with github.com/DWCarrot/caddy-basic-auth-ext=.` builds a standalone Caddy binary containing this checkout.
- `./caddy adapt --config ./Caddyfile.demo --adapter caddyfile --pretty --validate` validates the demo with that binary.
- `./caddy run --config ./Caddyfile.demo --adapter caddyfile` starts the demo; follow the README's requests to check authentication and permissions.

On Windows, use `./caddy.exe` and `curl.exe`. Run the demo from this root so its relative account path resolves correctly. Building the Go packages alone does not produce a Caddy executable.

## Coding and Testing

Use `gofmt`, standard Go naming, and the existing `basic_auth_ext` package name. Preserve Caddy module IDs, JSON field names, and directive syntax unless intentionally changing the public interface. Update README examples when configuration or behavior changes.

Add regression tests for changed behavior, especially malformed account records, group membership, failed authentication, and cache behavior. Use `t.TempDir()` for new file fixtures and check file-operation errors. Run build, tests, and vet for Go changes; also run `go test -race ./...` when changing shared caches or locking, using a supported race-detector toolchain.

## Authentication and Configuration

Account records contain whitespace-separated username, comma-separated groups, and a password hash. Group names are case-sensitive and currently must match `[a-zA-Z][a-zA-Z0-9_]*`. An empty required permission accepts any authenticated account. The `groups` user metadata contains the route's required permission, not all account groups.

Loaded account files are cached by absolute path for the process lifetime; restart after editing demo accounts. Preserve password hashing and the unknown-user fake-hash comparison. Keep real credentials, account files, `.env`, private keys, and generated binaries out of commits. Demo credentials are public test data only.

## Commits and Pull Requests

Use concise, descriptive commit subjects. Describe authentication or configuration changes and list validation results in PRs. Review this repository's `git status` and diff before committing, preserving unrelated edits. Commit module changes here before separately updating any parent submodule pointer.
