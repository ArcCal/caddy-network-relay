package networkrelay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters for new hashes: 19 MiB, 2 passes, 1 lane (OWASP).
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
)

const (
	okTTL         = 10 * time.Minute
	failTTL       = time.Minute
	maxCacheItems = 4096
)

// User is one account; each device gets its own.
type User struct {
	// User name: 1 to 64 letters, digits, '-', '_' or '.', not starting with '.'.
	Name string `json:"name"`
	// Argon2id hash in PHC format ("$argon2id$v=19$m=...") from
	// `caddy network-relay passwd`, or a bcrypt hash.
	PasswordHash string `json:"password_hash"`
}

func validateUserName(name string) error {
	if name == "" || len(name) > 64 || name[0] == '.' {
		return fmt.Errorf("user name %q must be 1 to 64 characters and not start with '.'", name)
	}
	for _, c := range []byte(name) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("user name %q may only contain letters, digits, '-', '_' and '.'", name)
		}
	}
	return nil
}

// passwordHash verifies passwords against one stored hash.
type passwordHash interface {
	verify(password []byte) bool
}

type argon2Hash struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

func (h *argon2Hash) verify(password []byte) bool {
	key := argon2.IDKey(password, h.salt, h.time, h.memory, h.threads, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(key, h.key) == 1
}

type bcryptHash []byte

func (h bcryptHash) verify(password []byte) bool {
	return bcrypt.CompareHashAndPassword(h, password) == nil
}

func parsePasswordHash(s string) (passwordHash, error) {
	// `caddy hash-password` prints the hash base64-encoded.
	if !strings.HasPrefix(s, "$") {
		if b, err := base64.StdEncoding.DecodeString(s); err == nil && strings.HasPrefix(string(b), "$") {
			s = string(b)
		}
	}
	if strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$") {
		cost, err := bcrypt.Cost([]byte(s))
		if err != nil {
			return nil, fmt.Errorf("invalid bcrypt hash: %v", err)
		}
		if cost > 14 {
			return nil, errors.New("bcrypt cost exceeds the relay verification budget (maximum 14)")
		}
		return bcryptHash(s), nil
	}
	// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, errors.New("password hash must be an Argon2id hash ($argon2id$...) or a bcrypt hash ($2b$...)")
	}
	if parts[2] != "v=19" {
		return nil, errors.New("only Argon2id version 19 is supported")
	}
	h := &argon2Hash{}
	seen := map[string]bool{}
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if !ok || err != nil || seen[k] {
			return nil, fmt.Errorf("invalid Argon2id parameter %q", kv)
		}
		seen[k] = true
		switch k {
		case "m":
			h.memory = uint32(n)
		case "t":
			h.time = uint32(n)
		case "p":
			if n > 255 {
				return nil, fmt.Errorf("invalid Argon2id parameter %q", kv)
			}
			h.threads = uint8(n)
		default:
			return nil, fmt.Errorf("unknown Argon2id parameter %q", kv)
		}
	}
	if h.time < 1 || h.threads < 1 || h.threads > 4 || h.memory < 8*uint32(h.threads) || h.memory > 64*1024 || h.time > 10 {
		return nil, errors.New("Argon2id parameters out of range")
	}
	var err error
	if h.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(h.salt) < 8 || len(h.salt) > 64 {
		return nil, errors.New("invalid Argon2id salt")
	}
	if h.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(h.key) < 16 || len(h.key) > 64 {
		return nil, errors.New("invalid Argon2id hash")
	}
	return h, nil
}

// HashPassword returns the Argon2id hash of password in PHC format.
func HashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// RandomPassword returns 144 random bits, base64url encoded (24 characters):
// impossible to guess online, so no lockout is needed.
func RandomPassword() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// BasicAuthorization is the Authorization header value for user/password.
func BasicAuthorization(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// credentials returns the Basic credentials of a request: from
// Proxy-Authorization, or else Authorization (where Apple devices put the
// header from the profile).
func credentials(r *http.Request) string {
	if v := r.Header.Get("Proxy-Authorization"); v != "" {
		return v
	}
	return r.Header.Get("Authorization")
}

func parseBasic(header string) (user, password string, ok bool) {
	scheme, value, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", "", false
	}
	return strings.Cut(string(raw), ":")
}

// account is a verified user: its name and the hash it was verified
// against. A tunnel stays open across a config reload only while some
// handler still has the same account.
type account struct {
	name string
	hash string
}

type cacheEntry struct {
	acct    account
	ok      bool
	expires time.Time
}

type flight struct {
	done chan struct{}
	acct account
	ok   bool
	// abandoned: the request went away before its verification ran, so
	// requests waiting for the result have to verify for themselves.
	abandoned bool
}

// pendingPerSlot bounds the verifications waiting for a slot: with 16 per
// slot, a request waits for at most about half a second (16 verifications
// of ~30 ms) before its own runs.
const pendingPerSlot = 16

// Bound expensive work process-wide, including configurations overlapping
// during reload. Respect container CPU quotas and cap normal Argon2 memory
// consumption at four concurrent verifications.
var authenticationSlots = make(chan struct{}, min(4, max(1, runtime.GOMAXPROCS(0))))
var authenticationPending = make(chan struct{}, pendingPerSlot*cap(authenticationSlots))

var (
	errBadCredentials = errors.New("wrong or missing credentials")
	errAuthBusy       = errors.New("too many verifications waiting")
)

// authenticator checks Basic credentials against the configured users.
// One Argon2id verification takes tens of milliseconds and devices send the
// same header with every request, so results are cached by an HMAC of the
// header (the cache never holds passwords): successes for 10 minutes,
// failures for a minute. Concurrent requests with the same header share one
// verification, and at most 2 per CPU run at once.
//
// Headers that are not cached cost a verification each, so they are bounded
// too: a request that goes away stops waiting (and its verification does
// not run), and when pendingPerSlot verifications per slot are already
// waiting, new ones are refused at once instead of queueing without limit.
// Devices whose header is cached are not affected either way.
type authenticator struct {
	users  map[string]User
	hashes map[string]passwordHash
	dummy  passwordHash

	key      []byte
	mu       sync.Mutex
	cache    map[[32]byte]cacheEntry
	inflight map[[32]byte]*flight
	slots    chan struct{}
}

func newAuthenticator(users []User) (*authenticator, error) {
	a := &authenticator{
		users:    map[string]User{},
		hashes:   map[string]passwordHash{},
		key:      make([]byte, 32),
		cache:    map[[32]byte]cacheEntry{},
		inflight: map[[32]byte]*flight{},
		slots:    authenticationSlots,
	}
	if _, err := rand.Read(a.key); err != nil {
		return nil, err
	}
	for _, u := range users {
		if err := validateUserName(u.Name); err != nil {
			return nil, err
		}
		if _, dup := a.users[u.Name]; dup {
			return nil, fmt.Errorf("user %q is defined twice", u.Name)
		}
		h, err := parsePasswordHash(u.PasswordHash)
		if err != nil {
			return nil, fmt.Errorf("user %q: %v", u.Name, err)
		}
		a.users[u.Name] = u
		a.hashes[u.Name] = h
	}
	// Unknown user names are checked against a random hash, so response
	// times do not reveal which names exist.
	dummy, err := parsePasswordHash(HashPassword(RandomPassword()))
	if err != nil {
		return nil, err
	}
	a.dummy = dummy
	return a, nil
}

// has reports whether acct is still a valid account here.
func (a *authenticator) has(acct account) bool {
	u, ok := a.users[acct.name]
	return ok && u.PasswordHash == acct.hash
}

// verify returns the account the header authenticates: errBadCredentials
// when it does not, errAuthBusy when too many verifications are waiting, or
// ctx's error when the request went away while waiting.
func (a *authenticator) verify(ctx context.Context, header string) (account, error) {
	if err := ctx.Err(); err != nil {
		return account{}, err
	}
	if header == "" || len(a.users) == 0 {
		return account{}, errBadCredentials
	}
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(header))
	var id [32]byte
	copy(id[:], mac.Sum(nil))
	admitted := false

	for {
		a.mu.Lock()
		if e, ok := a.cache[id]; ok {
			if time.Now().Before(e.expires) {
				a.mu.Unlock()
				return result(e.acct, e.ok)
			}
			delete(a.cache, id)
		}
		if !admitted {
			select {
			case authenticationPending <- struct{}{}:
				admitted = true
				defer func() { <-authenticationPending }()
			default:
				a.mu.Unlock()
				return account{}, errAuthBusy
			}
		}
		if f, ok := a.inflight[id]; ok {
			a.mu.Unlock()
			select {
			case <-f.done:
			case <-ctx.Done():
				return account{}, ctx.Err()
			}
			if f.abandoned {
				continue
			}
			return result(f.acct, f.ok)
		}
		if len(a.inflight) >= pendingPerSlot*cap(a.slots) {
			a.mu.Unlock()
			return account{}, errAuthBusy
		}
		f := &flight{done: make(chan struct{})}
		a.inflight[id] = f
		a.mu.Unlock()

		var err error
		f.acct, f.ok, err = a.check(ctx, header)

		a.mu.Lock()
		delete(a.inflight, id)
		if err != nil {
			f.abandoned = true
		} else {
			a.remember(id, f.acct, f.ok)
		}
		a.mu.Unlock()
		close(f.done)
		if err != nil {
			return account{}, err
		}
		return result(f.acct, f.ok)
	}
}

func result(acct account, ok bool) (account, error) {
	if !ok {
		return acct, errBadCredentials
	}
	return acct, nil
}

// check verifies header. It returns ctx's error, without verifying, when
// ctx ends while waiting for a slot.
func (a *authenticator) check(ctx context.Context, header string) (account, bool, error) {
	name, password, ok := parseBasic(header)
	if !ok {
		return account{}, false, nil
	}
	h, known := a.hashes[name]
	if !known {
		h = a.dummy
	}
	select {
	case a.slots <- struct{}{}:
	case <-ctx.Done():
		return account{}, false, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-a.slots
		return account{}, false, err
	}
	ok = h.verify([]byte(password))
	<-a.slots
	if !known || !ok {
		return account{name: name}, false, nil
	}
	return account{name: name, hash: a.users[name].PasswordHash}, true, nil
}

// remember caches a result. A full cache drops expired entries first; it
// never lets failures evict successes, so a flood of wrong credentials
// cannot force every device to be verified again.
func (a *authenticator) remember(id [32]byte, acct account, ok bool) {
	if len(a.cache) >= maxCacheItems {
		now := time.Now()
		for k, e := range a.cache {
			if now.After(e.expires) {
				delete(a.cache, k)
			}
		}
		if len(a.cache) >= maxCacheItems {
			if !ok {
				return
			}
			for k, e := range a.cache {
				if !e.ok {
					delete(a.cache, k)
					break
				}
			}
			if len(a.cache) >= maxCacheItems {
				return
			}
		}
	}
	ttl := failTTL
	if ok {
		ttl = okTTL
	}
	a.cache[id] = cacheEntry{acct: acct, ok: ok, expires: time.Now().Add(ttl)}
}
