# caddy-basic-auth-ext
extend caddy's basic auth module with file-recorded accounts (like nginx) and simple permission controls


## Usage

### Caddyfile

```
basic_auth_ext [<matcher>] [<hash_algorithm> [<realm>]] {
    file <filename>
    [permission <permission-group>]
}
```

### Account File

each line is a record of an account, split by blanks (space, tab, etc. can be one or more)

```
username    group1,group2,group3    hashed-password
```

`username` should be unique;

`groups` are comma-separated, group names are case-sensitive, should only contain alphanumeric characters and underscores

`hashed-password` is in Modular Crypt Format; for example, the result of `caddy hash-password --algorithm <hash_algorithm> --plaintext <password>`



## Local demo

[Caddyfile.demo](./Caddyfile.demo) uses [accounts-demo.txt](./accounts-demo.txt)
with bcrypt passwords. These credentials are intentionally public and only for demo use:

| Username | Password | Groups |
| --- | --- | --- |
| `test` | `demo-password-1` | `demo1,demo2` |
| `test2` | `demo-password-2` | `demo2` |

Use a custom Caddy binary containing this module. In the homelab-gateway checkout,
build it with the full command in the parent README, then run from this directory
so the relative accounts file path resolves correctly:

```sh
cd caddy-basic-auth-ext
../caddy adapt --config ./Caddyfile.demo --adapter caddyfile --pretty --validate
../caddy run --config ./Caddyfile.demo --adapter caddyfile
```

On Windows, use `../caddy.exe` for these commands and `curl.exe` for the requests
below. For a standalone module checkout, use your custom `caddy` binary instead.
The demo listens on `127.0.0.1:8080` over HTTP and disables the admin API. Stop it
with Ctrl+C.

### Test requests

Run these in another terminal; `-i` includes the HTTP status:

```sh
# 200: test belongs to demo1
curl -i -u test:demo-password-1 http://localhost:8080/test

# 401: test2 has valid credentials but does not belong to demo1
curl -i -u test2:demo-password-2 http://localhost:8080/test

# 200: both users belong to demo2
curl -i -u test:demo-password-1 http://localhost:8080/demo2
curl -i -u test2:demo-password-2 http://localhost:8080/demo2

# 200: no permission requirement; any valid account is accepted
curl -i -u test2:demo-password-2 http://localhost:8080/authenticated

# 401: missing or incorrect credentials
curl -i http://localhost:8080/test
curl -i -u test:wrong-password http://localhost:8080/test
```

A successful `/test` response is
`User authenticated with ID: test @ demo1`. The `{http.auth.user.groups}`
placeholder contains the route's required permission, not the account's complete
group list. Missing group membership returns 401, just like invalid credentials.

To generate a replacement bcrypt hash:

```sh
caddy hash-password --algorithm bcrypt --plaintext demo-password-1
```

Restart the demo after editing the accounts file; loaded accounts are cached for
the lifetime of the process.
