// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package basic_auth_ext

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("basic_auth_ext", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	basic_auth_ext [<matcher>] [<hash_algorithm> [<realm>]] {
//	    file <filename>
//	    [permission <permission-group>]
//	}
//
// If no hash algorithm is supplied, bcrypt will be assumed.
// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (hba *HTTPBasicAuthExt) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {

	d.Next() // consume directive name

	var cmp caddyauth.Comparer
	args := d.RemainingArgs()

	var hashName string
	switch len(args) {
	case 0:
		hashName = "bcrypt"
	case 1:
		hashName = args[0]
	case 2:
		hashName = args[0]
		hba.Realm = args[1]
	default:
		d.ArgErr()
	}

	switch hashName {
	case "bcrypt":
		cmp = caddyauth.BcryptHash{}
	default:
		return d.Errf("unrecognized hash algorithm: %s", hashName)
	}

	hba.HashRaw = caddyconfig.JSONModuleObject(cmp, "algorithm", hashName, nil)

	for d.NextBlock(0) {
		switch d.Val() {
		case "file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			hba.File = d.Val()
		case "permission":
			if !d.NextArg() {
				return d.ArgErr()
			}
			hba.Permission = d.Val()
		}
	}

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ba HTTPBasicAuthExt
	ba.HashCache = new(Cache)
	err := ba.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"http_basic_ext": caddyconfig.JSON(ba, nil),
		},
	}, nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*HTTPBasicAuthExt)(nil)
)
