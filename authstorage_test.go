package basic_auth_ext

import (
	"os"
	"testing"
)

func mapKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestParseAccountsFromFile(t *testing.T) {

	// acc1 = &AccountInfo{
	// 	Username: "test",
	// 	Password: []byte("testtest1"),
	// 	Groups:   map[string]struct{}{"demo1": struct{}{}, "demo2": struct{}{}},
	// }
	// acc2 = &AccountInfo{
	// 	Username: "test2",
	// 	Password: []byte("testtest2"),
	// 	Groups:   map[string]struct{}{"demo2": struct{}{}},
	// }

	fileRaw := `test    demo1,demo2     $2a$14$LfmwCC8zryYMswbPZ8MxDOi0.BJveyPHat6o4UGekAZd.o8ZQRMsa
test2   demo2           $2a$14$drZc7KI0tCqdG.0mNWTgl.KkH8thh4rI/QMdxt2/FJEWDPOdJ9fGq
`

	os.WriteFile("./accounts-temp0.txt", []byte(fileRaw), 0644)
	defer os.Remove("./accounts-temp0.txt")

	accounts, err := ParseAccountsFromFile("./accounts-temp0.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range accounts.Accounts {
		t.Logf("%s %s %s", account.Username, mapKeys(account.Groups), account.Password)
	}
}
