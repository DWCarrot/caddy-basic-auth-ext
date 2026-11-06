package basic_auth_ext

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"golang.org/x/crypto/bcrypt"
)

func TestCaddyfileConfiguration(t *testing.T) {
	var p HTTPBasicAuthExt
	if err := p.UnmarshalCaddyfile(caddyfile.NewTestDispenser("basic_auth_ext bcrypt restricted {\n file accounts.txt\n permission users\n}")); err != nil {
		t.Fatal(err)
	}
	if p.File != "accounts.txt" || p.Permission != "users" || p.Realm != "restricted" || !strings.Contains(string(p.HashRaw), "bcrypt") {
		t.Fatalf("unexpected config: %+v", p)
	}
	for _, input := range []string{"basic_auth_ext bcrypt realm extra", "basic_auth_ext unknown", "basic_auth_ext {\n file\n}", "basic_auth_ext {\n permission\n}", "basic_auth_ext {\n file a b\n}", "basic_auth_ext {\n permission a b\n}", "basic_auth_ext {\n unknown value\n}", "basic_auth_ext {\n file a {\n permission b\n }\n}"} {
		t.Run(input, func(t *testing.T) {
			var p HTTPBasicAuthExt
			if err := p.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestRegistrationAndReloadLifecycle(t *testing.T) {
	file := filepath.Join(t.TempDir(), "accounts.txt")
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("alice users "+string(hash)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	load := func(permission string) (*HTTPBasicAuthExt, context.CancelFunc) {
		t.Helper()
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		t.Cleanup(cancel)
		raw, err := json.Marshal(&HTTPBasicAuthExt{File: file, Permission: permission, HashCache: new(Cache)})
		if err != nil {
			t.Fatal(err)
		}
		mod, err := ctx.LoadModuleByID("http.authentication.providers.http_basic_ext", raw)
		if err != nil {
			t.Fatal(err)
		}
		return mod.(*HTTPBasicAuthExt), cancel
	}
	old, stopOld := load("users")
	next, _ := load("admins")
	if old.accounts != next.accounts || old.HashCache == next.HashCache {
		t.Fatal("expected shared accounts and independent password caches")
	}
	check := func(p *HTTPBasicAuthExt, password string, want bool) {
		t.Helper()
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth("alice", password)
		_, ok, err := p.Authenticate(httptest.NewRecorder(), req)
		if err != nil || ok != want {
			t.Fatalf("authentication: got %v, %v; want %v", ok, err, want)
		}
	}
	check(old, "test-password", true)
	check(next, "test-password", false)
	stopOld()
	check(next, "test-password", false)
	allowed, _ := load("users")
	check(allowed, "test-password", true)
	check(allowed, "wrong", false)
}

func TestCaddyReload(t *testing.T) {
	file := filepath.Join(t.TempDir(), "accounts.txt")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	for _, permission := range []string{"users", "admins"} {
		raw, _, err := (caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}).Adapt([]byte("{\n admin off\n auto_https off\n}\nhttp://127.0.0.1:0 {\n route {\n basic_auth_ext {\n file "+filepath.ToSlash(file)+"\n permission "+permission+"\n }\n respond ok\n }\n}"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"http_basic_ext"`) {
			t.Fatal("directive not registered")
		}
		if err := caddy.Load(raw, true); err != nil {
			t.Fatal(err)
		}
	}
}
