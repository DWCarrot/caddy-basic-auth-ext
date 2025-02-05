// modified from https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/caddyauth/caddyauth.go

package basic_auth_ext

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	weakrand "math/rand"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	caddy.RegisterModule(HTTPBasicAuthExt{})
}

// HTTPBasicAuthExt facilitates HTTP basic authentication.
type HTTPBasicAuthExt struct {
	// The algorithm with which the passwords are hashed. Default: bcrypt
	HashRaw json.RawMessage `json:"hash,omitempty" caddy:"namespace=http.authentication.hashes inline_key=algorithm"`

	// account file
	File string `json:"file,omitempty"`

	// permission (group) for this module
	Permission string `json:"permission,omitempty"`

	// The name of the realm. Default: restricted
	Realm string `json:"realm,omitempty"`

	// If non-nil, a mapping of plaintext passwords to their
	// hashes will be cached in memory (with random eviction).
	// This can greatly improve the performance of traffic-heavy
	// servers that use secure password hashing algorithms, with
	// the downside that plaintext passwords will be stored in
	// memory for a longer time (this should not be a problem
	// as long as your machine is not compromised, at which point
	// all bets are off, since basicauth necessitates plaintext
	// passwords being received over the wire anyway). Note that
	// a cache hit does not mean it is a valid password.
	HashCache *Cache `json:"hash_cache,omitempty"`

	// fakePassword is used when a given user is not found,
	// so that timing side-channels can be mitigated: it gives
	// us something to hash and compare even if the user does
	// not exist, which should have similar timing as a user
	// account that does exist.
	fakePassword []byte

	accounts *Accounts
}

// Cleanup implements caddy.CleanerUpper.
func (hba *HTTPBasicAuthExt) Cleanup() error {
	return nil
}

// CaddyModule returns the Caddy module information.
func (HTTPBasicAuthExt) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.authentication.providers.http_basic_ext",
		New: func() caddy.Module {
			return new(HTTPBasicAuthExt)
		},
	}
}

// Provision provisions the HTTP basic auth provider.
func (hba *HTTPBasicAuthExt) Provision(ctx caddy.Context) error {
	if hba.HashRaw == nil {
		hba.HashRaw = json.RawMessage(`{"algorithm": "bcrypt"}`)
	}

	// load password hasher
	hasherIface, err := ctx.LoadModule(hba, "HashRaw")
	if err != nil {
		return fmt.Errorf("loading password hasher module: %v", err)
	}
	var hash = hasherIface.(caddyauth.Comparer)

	if hash == nil {
		return fmt.Errorf("hash is required")
	}

	// if supported, generate a fake password we can compare against if needed
	if hasher, ok := hash.(caddyauth.Hasher); ok {
		hba.fakePassword = hasher.FakeHash()
	}

	repl := caddy.NewReplacer()

	if hba.File != "" {
		hba.File = repl.ReplaceAll(hba.File, "")
	}

	// load account list
	mgr := GetAccountMangerInstance()
	hba.accounts, err = mgr.Load(hba.File, hash)
	if err != nil {
		return err
	}

	if hba.HashCache != nil {
		hba.HashCache.inner = hash
		hba.HashCache.cache = make(map[string]bool)
	}

	return nil
}

// Authenticate validates the user credentials in req and returns the user, if valid.
func (hba HTTPBasicAuthExt) Authenticate(w http.ResponseWriter, req *http.Request) (caddyauth.User, bool, error) {
	username, plaintextPasswordStr, ok := req.BasicAuth()
	if !ok {
		return hba.promptForCredentials(w, nil)
	}

	account := hba.accounts.GetAccount(username)
	var hashedPassword []byte
	if account == nil {
		// don't return early if account does not exist; we want
		// to try to avoid side-channels that leak existence, so
		// we use a fake password to simulate realistic CPU cycles
		hashedPassword = hba.fakePassword
	} else {
		hashedPassword = account.Password
	}

	// check password
	var same bool
	var err error
	plaintextPassword := []byte(plaintextPasswordStr)
	if hba.HashCache != nil {
		same, err = hba.HashCache.Compare(hashedPassword, plaintextPassword)
	} else {
		same, err = hba.accounts.Hash.Compare(hashedPassword, plaintextPassword)
	}
	if err != nil {
		return caddyauth.User{}, false, err
	}
	if !same || account == nil {
		return hba.promptForCredentials(w, err)
	}

	// check groups
	user := caddyauth.User{ID: account.Username}
	if !account.InGroup(hba.Permission) {
		return user, false, nil
	}
	user.Metadata = map[string]string{
		"groups": hba.Permission,
	}
	return user, true, nil
}

func (hba *HTTPBasicAuthExt) promptForCredentials(w http.ResponseWriter, err error) (caddyauth.User, bool, error) {
	// browsers show a message that says something like:
	// "The website says: <realm>"
	// which is kinda dumb, but whatever.
	realm := hba.Realm
	if realm == "" {
		realm = "restricted"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	return caddyauth.User{}, false, err
}

// Cache enables caching of basic auth results. This is especially
// helpful for secure password hashes which can be expensive to
// compute on every HTTP request.
type Cache struct {
	mu sync.RWMutex

	// map of concatenated hashed password + plaintext password, to result
	cache map[string]bool

	// real hash comparer
	inner caddyauth.Comparer
}

// Compare implements caddyauth.Comparer.
func (c *Cache) Compare(hashedPassword []byte, plaintextPassword []byte) (bool, error) {
	cacheKey := c.genKey(hashedPassword, plaintextPassword)

	c.mu.RLock()
	same, ok := c.cache[cacheKey]
	c.mu.RUnlock()
	if ok {
		return same, nil
	}

	// slow track: do the expensive op, then add it to the cache
	// but perform it in a singleflight group so that multiple
	// parallel requests using the same password don't cause a
	// thundering herd problem by all performing the same hashing
	// operation before the first one finishes and caches it.
	c.mu.Lock()
	defer c.mu.Unlock()
	same, ok = c.cache[cacheKey]
	if ok {
		return same, nil
	}
	var err error
	same, err = c.inner.Compare(hashedPassword, plaintextPassword)
	if err != nil {
		return false, err
	}

	if len(c.cache) >= 256 {
		c.makeRoom() // keep cache size under control
	}
	c.cache[cacheKey] = same

	return same, err
}

func (c *Cache) genKey(hashedPassword []byte, plaintextPassword []byte) string {
	return hex.EncodeToString(append(hashedPassword, plaintextPassword...))
}

// makeRoom deletes about 1/10 of the items in the cache
// in order to keep its size under control. It must not be
// called without a lock on c.mu.
func (c *Cache) makeRoom() {
	// we delete more than just 1 entry so that we don't have
	// to do this on every request; assuming the capacity of
	// the cache is on a long tail, we can save a lot of CPU
	// time by doing a whole bunch of deletions now and then
	// we won't have to do them again for a while
	numToDelete := len(c.cache) / 10
	if numToDelete < 1 {
		numToDelete = 1
	}
	for deleted := 0; deleted <= numToDelete; deleted++ {
		// Go maps are "nondeterministic" not actually random,
		// so although we could just chop off the "front" of the
		// map with less code, this is a heavily skewed eviction
		// strategy; generating random numbers is cheap and
		// ensures a much better distribution.
		//nolint:gosec
		rnd := weakrand.Intn(len(c.cache))
		i := 0
		for key := range c.cache {
			if i == rnd {
				delete(c.cache, key)
				break
			}
			i++
		}
	}
}

// Interface guards
var (
	_ caddy.Provisioner       = (*HTTPBasicAuthExt)(nil)
	_ caddy.CleanerUpper      = (*HTTPBasicAuthExt)(nil)
	_ caddyauth.Authenticator = (*HTTPBasicAuthExt)(nil)

	_ caddyauth.Comparer = (*Cache)(nil)
)
