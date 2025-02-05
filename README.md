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

`hashed-password` is in Modular Crypt Format; for example, the result of `caddy hash-password --algorithm <hash_algorithm> <password>`



## Sample Caddyfile & Account File

### Caddyfile

```

{
	order basic_auth_ext before basic_auth
}

api.example.com {
	route /test {

		basic_auth_ext {
			file /path/to/accounts-demo.txt
			permission demo1
		}


		respond "User authenticated with ID: {http.auth.user.id} @ {http.auth.user.groups}"
	}
}

```

### Account

`accounts-demo.txt`

```
test    demo1,demo2     $2a$14$LfmwCC8zryYMswbPZ8MxDOi0.BJveyPHat6o4UGekAZd.o8ZQRMsa
test2   demo2           $2a$14$drZc7KI0tCqdG.0mNWTgl.KkH8thh4rI/QMdxt2/FJEWDPOdJ9fGq
```
