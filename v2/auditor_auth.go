/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor web auth: bcrypt-verified users, in-memory session store,
 * HMAC-signed cookies. Sliding idle timeout: each request bumps
 * expiry forward; missing/expired cookie → redirect to /web/login.
 *
 * Threat model: small public deployments. Sessions are not persisted
 * — restart logs everyone out. CSRF defended by SameSite=Strict on
 * the session cookie + read-only data routes. The only POST is
 * /web/login; /web/logout is GET (idempotent).
 */
package tdnsmp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	sessionCookieName = "tdns_auditor_session"
	defaultIdleTTL    = 30 * time.Minute
	sessionIDBytes    = 32
)

// AuditWebUser is one configured user.
type AuditWebUser struct {
	Name         string `yaml:"name" json:"name"`
	PasswordHash string `yaml:"password_hash" json:"password_hash"` // bcrypt
}

// AuditWebSession is an active session.
type AuditWebSession struct {
	ID        string
	User      string
	ExpiresAt time.Time
}

// AuditWebAuth holds users + sessions + signing key.
type AuditWebAuth struct {
	mu       sync.Mutex
	users    map[string]string // name → bcrypt hash
	sessions map[string]*AuditWebSession
	signKey  []byte
	idleTTL  time.Duration
}

// NewAuditWebAuth builds an auth context from configured users +
// idle TTL. signKey is generated fresh on each start; cookies do not
// survive restart by design.
func NewAuditWebAuth(users []AuditWebUser, idleTTL time.Duration) (*AuditWebAuth, error) {
	if idleTTL <= 0 {
		idleTTL = defaultIdleTTL
	}
	if len(users) == 0 {
		return nil, errors.New("no users configured")
	}
	signKey := make([]byte, 32)
	if _, err := rand.Read(signKey); err != nil {
		return nil, fmt.Errorf("session signing key: %w", err)
	}
	a := &AuditWebAuth{
		users:    make(map[string]string, len(users)),
		sessions: make(map[string]*AuditWebSession),
		signKey:  signKey,
		idleTTL:  idleTTL,
	}
	if err := a.replaceUsers(users); err != nil {
		return nil, err
	}
	return a, nil
}

// replaceUsers atomically swaps the in-memory user map under the
// lock. Caller validates count > 0.
func (a *AuditWebAuth) replaceUsers(users []AuditWebUser) error {
	next := make(map[string]string, len(users))
	for _, u := range users {
		if u.Name == "" || u.PasswordHash == "" {
			return fmt.Errorf("user %q has empty name or password_hash", u.Name)
		}
		next[u.Name] = u.PasswordHash
	}
	a.mu.Lock()
	a.users = next
	a.mu.Unlock()
	return nil
}

// ReloadFromFile re-reads the users file at path and atomically
// swaps the in-memory user map. Existing sessions are not affected.
func (a *AuditWebAuth) ReloadFromFile(path string) (int, error) {
	users, err := ReadAuditWebUsersFile(path)
	if err != nil {
		return 0, err
	}
	if len(users) == 0 {
		return 0, errors.New("user file has no users; refusing to reload to empty set")
	}
	if err := a.replaceUsers(users); err != nil {
		return 0, err
	}
	return len(users), nil
}

// auditWebUsersFileFormat is the on-disk schema for the user file.
type auditWebUsersFileFormat struct {
	Users []AuditWebUser `yaml:"users"`
}

// ReadAuditWebUsersFile parses the YAML file at path. Returns an
// empty slice (not an error) if the file does not exist.
func ReadAuditWebUsersFile(path string) ([]AuditWebUser, error) {
	if path == "" {
		return nil, errors.New("users file path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f auditWebUsersFileFormat
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for i, u := range f.Users {
		if u.Name == "" || u.PasswordHash == "" {
			return nil, fmt.Errorf("%s: user %d has empty name or password_hash", path, i)
		}
	}
	return f.Users, nil
}

// WriteAuditWebUsersFile atomically writes users to path. If the
// file does not exist it is created with mode 0600; if it does, the
// existing mode is preserved. Writes go to a sibling tempfile and
// are renamed into place to avoid a partial-write window.
func WriteAuditWebUsersFile(path string, users []AuditWebUser) error {
	if path == "" {
		return errors.New("users file path is empty")
	}
	for i, u := range users {
		if u.Name == "" || u.PasswordHash == "" {
			return fmt.Errorf("user %d has empty name or password_hash", i)
		}
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	out, err := yaml.Marshal(auditWebUsersFileFormat{Users: users})
	if err != nil {
		return fmt.Errorf("marshal users: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tdns-auditor-users-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// HashPassword returns a bcrypt hash at cost 12.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("empty password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// Verify checks user/password against the bcrypt hash. Returns nil on success.
func (a *AuditWebAuth) Verify(user, password string) error {
	a.mu.Lock()
	hash, ok := a.users[user]
	a.mu.Unlock()
	if !ok {
		// Run bcrypt anyway to avoid timing leaks of which usernames exist.
		_ = bcrypt.CompareHashAndPassword(
			[]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidi"),
			[]byte(password),
		)
		return errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return errors.New("invalid credentials")
	}
	return nil
}

// CreateSession allocates a new session for user and returns the
// signed cookie value the client should receive.
func (a *AuditWebAuth) CreateSession(user string) (string, *AuditWebSession, error) {
	idBytes := make([]byte, sessionIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return "", nil, fmt.Errorf("session id: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	sess := &AuditWebSession{
		ID:        id,
		User:      user,
		ExpiresAt: time.Now().Add(a.idleTTL),
	}
	a.mu.Lock()
	a.sessions[id] = sess
	a.mu.Unlock()
	return a.sign(id), sess, nil
}

// LookupAndBump returns the session for a signed cookie value, sliding
// the expiry forward by idleTTL. Returns nil if missing/expired.
func (a *AuditWebAuth) LookupAndBump(signedCookie string) *AuditWebSession {
	id, ok := a.verify(signedCookie)
	if !ok {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, ok := a.sessions[id]
	if !ok {
		return nil
	}
	if time.Now().After(sess.ExpiresAt) {
		delete(a.sessions, id)
		return nil
	}
	sess.ExpiresAt = time.Now().Add(a.idleTTL)
	return sess
}

// Logout deletes the session matching signedCookie. Idempotent.
func (a *AuditWebAuth) Logout(signedCookie string) {
	id, ok := a.verify(signedCookie)
	if !ok {
		return
	}
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
}

// PruneExpired drops expired sessions. Call from a periodic ticker.
func (a *AuditWebAuth) PruneExpired() {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, sess := range a.sessions {
		if now.After(sess.ExpiresAt) {
			delete(a.sessions, id)
		}
	}
}

// sign builds "id.mac" where mac = HMAC-SHA256(signKey, id), base64url.
func (a *AuditWebAuth) sign(id string) string {
	mac := hmac.New(sha256.New, a.signKey)
	mac.Write([]byte(id))
	return id + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verify parses "id.mac" and returns id if the MAC checks out.
func (a *AuditWebAuth) verify(signed string) (string, bool) {
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	id, macB64 := parts[0], parts[1]
	got, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, a.signKey)
	mac.Write([]byte(id))
	want := mac.Sum(nil)
	if !hmac.Equal(got, want) {
		return "", false
	}
	return id, true
}

// SetSessionCookie writes the signed-cookie response header. secure
// controls the Secure flag (set false only when serving plain HTTP
// in lab; production must run HTTPS).
func SetSessionCookie(w http.ResponseWriter, signed string, idleTTL time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signed,
		Path:     "/web/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(idleTTL),
	})
}

// ClearSessionCookie blanks the session cookie on logout.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/web/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// IdleTTL returns the configured idle timeout (read-only).
func (a *AuditWebAuth) IdleTTL() time.Duration { return a.idleTTL }
