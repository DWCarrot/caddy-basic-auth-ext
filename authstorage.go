package basic_auth_ext

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

var patternCheckGroup = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

func AccountInfoCheckGroup(group string) bool {
	return patternCheckGroup.MatchString(group)
}

type Account struct {

	// A user's username.
	Username string

	// The user's hashed password,

	Password []byte

	// A user's groups. used as set of strings;
	// group names are case-sensitive, should only contain alphanumeric characters and underscores
	// Stored in
	Groups map[string]struct{}
}

// Check if a user is in a group; if group is empty, always return true
func (info *Account) InGroup(group string) bool {
	if group == "" {
		return true
	}
	if info.Groups == nil {
		return false
	}
	_, ok := info.Groups[group]
	return ok
}

// Add a group to a user
func (info *Account) AddGroup(group string) bool {
	if !AccountInfoCheckGroup(group) {
		return false
	}
	if info.Groups == nil {
		info.Groups = make(map[string]struct{})
	}
	info.Groups[group] = struct{}{}
	return true
}

// Remove a group from a user
func (info *Account) RemoveGroup(group string) {
	delete(info.Groups, group)
}

// Accounts is a list of accounts from one file
type Accounts struct {

	// The file path
	File string

	// The hash algorithm used to hash the passwords
	Hash caddyauth.Comparer

	// The accounts in the file
	Accounts map[string]*Account
}

func (a *Accounts) GetAccount(username string) *Account {
	val, ok := a.Accounts[username]
	if !ok {
		return nil
	}
	return val
}

func ParseAccountsFromFile(filePath string, hash caddyauth.Comparer) (*Accounts, error) {

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := &Accounts{
		File:     filePath,
		Hash:     hash,
		Accounts: make(map[string]*Account),
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		parts := bytes.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid line: %s", line)
		}
		account := &Account{
			Username: string(parts[0]),
			Password: nil,
			Groups:   make(map[string]struct{}),
		}
		groups := string(parts[1])
		for _, group := range strings.Split(groups, ",") {
			if !account.AddGroup(group) {
				return nil, fmt.Errorf("invalid group: %s", group)
			}
		}
		account.Password = parts[2]
		result.Accounts[account.Username] = account
	}
	return result, scanner.Err()
}

type AccountManager struct {
	cache map[string]*Accounts
	mu    sync.RWMutex
}

func NewAccountManager() *AccountManager {
	return &AccountManager{
		cache: make(map[string]*Accounts),
	}
}

func (m *AccountManager) Load(filePath string, hash caddyauth.Comparer) (*Accounts, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}
	absPath = filepath.Clean(absPath)

	m.mu.RLock()
	// Check if file is cached
	if data, exists := m.cache[absPath]; exists {
		defer m.mu.RUnlock()
		cachedHashType := reflect.TypeOf(data.Hash)
		targetHashType := reflect.TypeOf(hash)
		if cachedHashType != targetHashType {
			return nil, fmt.Errorf("hash algorithm changed: cached %s, got %s", cachedHashType, targetHashType)
		}
		// Return the cached file data
		return data, nil
	}
	m.mu.RUnlock()

	// If not cached, load it
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check if the file was loaded by another goroutine
	if data, exists := m.cache[absPath]; exists {
		return data, nil
	}

	// Load the file and cache the result
	data, err := ParseAccountsFromFile(absPath, hash)
	if err != nil {
		return nil, err
	}

	// Cache the loaded data
	m.cache[absPath] = data
	return data, nil
}

var GetAccountMangerInstance = sync.OnceValue(NewAccountManager)
