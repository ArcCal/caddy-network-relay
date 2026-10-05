package networkrelay

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// Password hash from `caddy network-relay passwd`: PBKDF2-SHA256
	// ("$pbkdf2-sha256$i=1000,l=32$...") for a generated password, Argon2id
	// ("$argon2id$v=19$m=...") for a chosen one, or a bcrypt hash. Optional
	// when CertificateSHA256 is set.
	PasswordHash string `json:"password_hash,omitempty"`
	// SHA-256 fingerprint (hex) of the user's TLS client certificate, from
	// `caddy network-relay identity`. The site's TLS connection policy must
	// request client certificates (client_auth { mode request }).
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
	// When the account stops working (RFC 3339); its tunnels close then.
	Expires string `json:"expires,omitempty"`
}

// credential identifies what a user authenticates with, so that a tunnel
// outlives a reload only while its user's credentials are unchanged.
func (u User) credential() string {
	return u.PasswordHash + "|" + strings.ToLower(u.CertificateSHA256) + "|" + u.Expires
}

// parseFingerprint reads a SHA-256 fingerprint: 64 hex digits, optionally
// separated by colons.
func parseFingerprint(s string) ([32]byte, error) {
	var fp [32]byte
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if err != nil || len(b) != len(fp) {
		return fp, fmt.Errorf("%q is not a SHA-256 fingerprint (64 hex digits)", s)
	}
	copy(fp[:], b)
	return fp, nil
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

// pbkdf2Hash is for generated secrets, which are too random to guess
// online or from a stolen hash: a slow hash would only cost the server.
type pbkdf2Hash struct {
	iterations int
	salt, key  []byte
}

func (h *pbkdf2Hash) verify(password []byte) bool {
	key, err := pbkdf2.Key(sha256.New, string(password), h.salt, h.iterations, len(h.key))
	return err == nil && subtle.ConstantTimeCompare(key, h.key) == 1
}

// Fast hashes, interchangeable with the Rust relay's:
// $pbkdf2-sha256$i=1000,l=32$<salt>$<hash>, base64 without padding.
const (
	fastHashIterations = 1000
	minGeneratedSecret = 24
)

func parsePBKDF2(s string) (passwordHash, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "pbkdf2-sha256" {
		return nil, errors.New("invalid PBKDF2 hash")
	}
	h := &pbkdf2Hash{}
	var length int
	for _, kv := range strings.Split(parts[2], ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.Atoi(v)
		if !ok || err != nil {
			return nil, fmt.Errorf("invalid PBKDF2 parameter %q", kv)
		}
		switch k {
		case "i":
			h.iterations = n
		case "l":
			length = n
		default:
			return nil, fmt.Errorf("unknown PBKDF2 parameter %q", kv)
		}
	}
	if h.iterations < fastHashIterations || h.iterations > 1_000_000 || length != 32 {
		return nil, errors.New("PBKDF2 parameters out of range (1000 to 1000000 iterations, 32 bytes)")
	}
	var err error
	if h.salt, err = base64.RawStdEncoding.DecodeString(parts[3]); err != nil || len(h.salt) < 8 || len(h.salt) > 64 {
		return nil, errors.New("invalid PBKDF2 salt")
	}
	if h.key, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(h.key) != length {
		return nil, errors.New("invalid PBKDF2 hash")
	}
	return h, nil
}

// HashGeneratedSecret returns the fast hash of a random secret of at least
// 24 characters, such as RandomPassword makes.
func HashGeneratedSecret(secret string) (string, error) {
	if len(secret) < minGeneratedSecret {
		return "", fmt.Errorf("a secret for the fast hash needs at least %d characters", minGeneratedSecret)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, secret, salt, fastHashIterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$pbkdf2-sha256$i=%d,l=32$%s$%s", fastHashIterations,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
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
	if strings.HasPrefix(s, "$pbkdf2-sha256$") {
		return parsePBKDF2(s)
	}
	// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, errors.New("password hash must be a PBKDF2 ($pbkdf2-sha256$...), Argon2id ($argon2id$...) or bcrypt ($2b$...) hash")
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

// account is a verified user: its name and the credentials it was verified
// against. A tunnel stays open across a config reload only while some
// handler still has the same account.
type account struct {
	name string
	// hash is the user's credential identity (User.credential).
	hash    string
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

// authenticationPending counts verifications that will need a hash: only a
// request that starts one takes a place, never one that waits for another
// request's verification of the same header.
var authenticationPending = make(chan struct{}, pendingPerSlot*cap(authenticationSlots))

// Sharing a hash avoids costly work, but each waiting request still holds a
// handler goroutine and its transport stream. Bound these cheap waiters
// separately, without charging another hash or client-attempt token.
var authenticationWaiters = make(chan struct{}, 4096)

var (
	errBadCredentials = errors.New("wrong or missing credentials")
	errAuthBusy       = errors.New("too many verifications waiting")
)

// Limits on new credentials, which cost a hash each. Credentials that
// already passed cost nothing and are never limited.
const (
	// Per client address (IPv4 address or IPv6 /64): about one new
	// credential a second, after a burst of 30.
	attemptRate    = 1.0
	attemptBurst   = 30
	attemptClients = 65536
	// Per connection: new credentials being checked at once.
	pendingPerConnection = 4
)

// connState is what the relay tracks per client connection.
type connState struct {
	pending atomic.Int32
}

type connStateKey struct{}

// withConnState gives a connection's requests their connState (a
// ConnContext hook for HTTP/1.1, HTTP/2 and HTTP/3).
func withConnState(ctx context.Context) context.Context {
	return context.WithValue(ctx, connStateKey{}, &connState{})
}

// requester is where a request comes from, for the limits on new
// credentials.
type requester struct {
	ip   netip.Addr // invalid when unknown
	conn *connState // nil when unknown
}

func clientOf(r *http.Request) requester {
	c := requester{}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		c.ip = ap.Addr()
	}
	c.conn, _ = r.Context().Value(connStateKey{}).(*connState)
	return c
}

// attemptBuckets limits new credentials per client address.
var attemptBuckets = struct {
	sync.Mutex
	m map[netip.Prefix]*attemptBucket
}{m: map[netip.Prefix]*attemptBucket{}}

type attemptBucket struct {
	tokens float64
	last   time.Time
}

func (b *attemptBucket) refill(now time.Time) {
	b.tokens = min(attemptBurst, b.tokens+now.Sub(b.last).Seconds()*attemptRate)
	b.last = now
}

func clientPrefix(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	if ip.Is4() {
		return netip.PrefixFrom(ip, 32)
	}
	p, _ := ip.WithZone("").Prefix(64)
	return p
}

// allowAttempt reports whether ip may have one more credential checked.
// While too many addresses are tracked at once (a flood from many
// addresses), new ones are refused until older buckets have filled up
// again and are forgotten.
func allowAttempt(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	key := clientPrefix(ip)
	now := time.Now()
	attemptBuckets.Lock()
	defer attemptBuckets.Unlock()
	b, ok := attemptBuckets.m[key]
	if !ok {
		if len(attemptBuckets.m) >= attemptClients {
			for k, old := range attemptBuckets.m {
				if old.refill(now); old.tokens >= attemptBurst {
					delete(attemptBuckets.m, k)
				}
			}
			if len(attemptBuckets.m) >= attemptClients {
				return false
			}
		}
		b = &attemptBucket{tokens: attemptBurst, last: now}
		attemptBuckets.m[key] = b
	}
	b.refill(now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// verified caches successful verifications for the life of the process,
// across configuration reloads, keyed by an HMAC of the header with a
// random key (the cache never holds passwords). An entry counts only for
// an authenticator that still has the same account, so a reload that
// leaves a user alone does not make its devices verify again, while one
// that removes or changes the user does. Entries last okTTL from their
// last use.
var verified = struct {
	sync.Mutex
	key []byte
	m   map[[32]byte]verifiedEntry
}{key: randomKey(), m: map[[32]byte]verifiedEntry{}}

type verifiedEntry struct {
	acct    account
	expires time.Time
}

func randomKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

func headerID(header string) [32]byte {
	mac := hmac.New(sha256.New, verified.key)
	mac.Write([]byte(header))
	var id [32]byte
	copy(id[:], mac.Sum(nil))
	return id
}

// authenticator checks credentials against the configured users: Basic
// passwords and client certificate fingerprints. A password verification
// takes tens of milliseconds for Argon2id and devices send the same header
// with every request, so successes are cached for the process (see
// verified) and failures here for a minute. Concurrent requests with the
// same header share one verification, and at most 4 run at once.
//
// New headers cost a verification each, so they are limited: per client
// address (attemptRate), per connection (pendingPerConnection) and in total
// (authenticationPending); over the limits a request is refused at once
// instead of queueing without limit. A request that goes away stops waiting,
// and its verification does not run. Devices whose header is cached are not
// affected either way.
type authenticator struct {
	users     map[string]User
	creds     map[string]string
	expires   map[string]time.Time
	hashes    map[string]passwordHash
	certs     map[[32]byte]string
	dummy     passwordHash
	fastDummy bool

	mu       sync.Mutex
	failed   map[[32]byte]time.Time
	inflight map[[32]byte]*flight
	slots    chan struct{}
}

func newAuthenticator(users []User) (*authenticator, error) {
	a := &authenticator{
		users:    map[string]User{},
		creds:    map[string]string{},
		expires:  map[string]time.Time{},
		hashes:   map[string]passwordHash{},
		certs:    map[[32]byte]string{},
		failed:   map[[32]byte]time.Time{},
		inflight: map[[32]byte]*flight{},
		slots:    authenticationSlots,
	}
	allFast := true
	for _, u := range users {
		if err := validateUserName(u.Name); err != nil {
			return nil, err
		}
		if _, dup := a.users[u.Name]; dup {
			return nil, fmt.Errorf("user %q is defined twice", u.Name)
		}
		if u.PasswordHash == "" && u.CertificateSHA256 == "" {
			return nil, fmt.Errorf("user %q needs a password hash, a certificate fingerprint, or both", u.Name)
		}
		if u.PasswordHash != "" {
			h, err := parsePasswordHash(u.PasswordHash)
			if err != nil {
				return nil, fmt.Errorf("user %q: %v", u.Name, err)
			}
			a.hashes[u.Name] = h
			if _, fast := h.(*pbkdf2Hash); !fast {
				allFast = false
			}
		}
		if u.CertificateSHA256 != "" {
			fp, err := parseFingerprint(u.CertificateSHA256)
			if err != nil {
				return nil, fmt.Errorf("user %q: %v", u.Name, err)
			}
			if other, dup := a.certs[fp]; dup {
				return nil, fmt.Errorf("users %q and %q have the same certificate", other, u.Name)
			}
			a.certs[fp] = u.Name
		}
		if u.Expires != "" {
			t, err := time.Parse(time.RFC3339, strings.TrimSpace(u.Expires))
			if err != nil {
				return nil, fmt.Errorf("user %q: expires %q is not an RFC 3339 time such as 2027-01-31T00:00:00Z", u.Name, u.Expires)
			}
			a.expires[u.Name] = t
		}
		a.users[u.Name] = u
		a.creds[u.Name] = u.credential()
	}
	// Unknown user names are checked against a random hash of the same
	// kind as the configured ones, so response times do not reveal which
	// names exist.
	a.fastDummy = len(a.hashes) > 0 && allFast
	dummyHash := HashPassword(RandomPassword())
	if a.fastDummy {
		var err error
		if dummyHash, err = HashGeneratedSecret(RandomPassword()); err != nil {
			return nil, err
		}
	}
	dummy, err := parsePasswordHash(dummyHash)
	if err != nil {
		return nil, err
	}
	a.dummy = dummy
	return a, nil
}

// accountOf is the account of a configured user.
func (a *authenticator) accountOf(name string) account {
	return account{name: name, hash: a.creds[name], expires: a.expires[name]}
}

// has reports whether acct is still a valid account here: the user exists
// with the same credentials and has not expired.
func (a *authenticator) has(acct account) bool {
	cred, ok := a.creds[acct.name]
	if !ok || cred != acct.hash {
		return false
	}
	exp := a.expires[acct.name]
	return exp.IsZero() || time.Now().Before(exp)
}

// verifyCertificate returns the account of the client certificate
// fingerprint, if a user has it.
func (a *authenticator) verifyCertificate(fp [32]byte) (account, bool) {
	name, ok := a.certs[fp]
	if !ok {
		return account{}, false
	}
	acct := a.accountOf(name)
	return acct, a.has(acct)
}

// verify checks a header with no limits per client; see verifyFrom.
func (a *authenticator) verify(ctx context.Context, header string) (account, error) {
	return a.verifyFrom(ctx, header, requester{})
}

// verifyFrom returns the account the header authenticates: errBadCredentials
// when it does not, errAuthBusy when new credentials from this client, on
// this connection or overall are over their limits, or ctx's error when the
// request went away while waiting.
func (a *authenticator) verifyFrom(ctx context.Context, header string, from requester) (account, error) {
	if err := ctx.Err(); err != nil {
		return account{}, err
	}
	if header == "" || len(a.hashes) == 0 {
		return account{}, errBadCredentials
	}
	id := headerID(header)
	for {
		if err := ctx.Err(); err != nil {
			return account{}, err
		}
		if acct, ok := a.cached(id); ok {
			if err := ctx.Err(); err != nil {
				return account{}, err
			}
			return acct, nil
		}
		a.mu.Lock()
		if until, ok := a.failed[id]; ok {
			if time.Now().Before(until) {
				a.mu.Unlock()
				return account{}, errBadCredentials
			}
			delete(a.failed, id)
		}
		if f, ok := a.inflight[id]; ok {
			// Sharing this hash uses only a bounded cheap-waiter place.
			select {
			case authenticationWaiters <- struct{}{}:
			default:
				a.mu.Unlock()
				return account{}, errAuthBusy
			}
			a.mu.Unlock()
			select {
			case <-f.done:
			case <-ctx.Done():
				<-authenticationWaiters
				return account{}, ctx.Err()
			}
			<-authenticationWaiters
			if f.abandoned {
				continue
			}
			if err := ctx.Err(); err != nil {
				return account{}, err
			}
			return result(f.acct, f.ok)
		}
		release, err := a.admit(from)
		if err != nil {
			a.mu.Unlock()
			return account{}, err
		}
		f := &flight{done: make(chan struct{})}
		a.inflight[id] = f
		a.mu.Unlock()

		f.acct, f.ok, err = a.check(ctx, header)

		a.mu.Lock()
		delete(a.inflight, id)
		if err != nil {
			f.abandoned = true
		} else {
			a.remember(id, f.acct, f.ok)
		}
		a.mu.Unlock()
		release()
		close(f.done)
		if err != nil {
			return account{}, err
		}
		return result(f.acct, f.ok)
	}
}

// admit takes the places a new verification needs: one of the connection's,
// a token of the client address and one of the process's. Called with a.mu.
func (a *authenticator) admit(from requester) (func(), error) {
	if from.conn != nil {
		if from.conn.pending.Add(1) > pendingPerConnection {
			from.conn.pending.Add(-1)
			return nil, errAuthBusy
		}
	}
	releaseConn := func() {
		if from.conn != nil {
			from.conn.pending.Add(-1)
		}
	}
	if len(a.inflight) >= pendingPerSlot*cap(a.slots) || !allowAttempt(from.ip) {
		releaseConn()
		return nil, errAuthBusy
	}
	select {
	case authenticationPending <- struct{}{}:
	default:
		releaseConn()
		return nil, errAuthBusy
	}
	return func() {
		<-authenticationPending
		releaseConn()
	}, nil
}

// cached returns the account of a header verified before, if it is still
// valid here, and extends its life.
func (a *authenticator) cached(id [32]byte) (account, bool) {
	verified.Lock()
	defer verified.Unlock()
	e, ok := verified.m[id]
	now := time.Now()
	if !ok || now.After(e.expires) {
		return account{}, false
	}
	if !a.has(e.acct) {
		return account{}, false
	}
	e.expires = now.Add(okTTL)
	verified.m[id] = e
	return e.acct, true
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
	// Hash functions cannot stop midway. Once that bounded work finishes,
	// cancellation must still win rather than authenticate a dead request.
	if err := ctx.Err(); err != nil {
		return account{}, false, err
	}
	if !known || !ok {
		return account{name: name}, false, nil
	}
	acct := a.accountOf(name)
	return acct, a.has(acct), nil
}

// remember caches a result: successes for the process, failures here. A
// full cache drops expired entries first; failures never evict successes,
// so a flood of wrong credentials cannot force every device to be verified
// again. Called with a.mu.
func (a *authenticator) remember(id [32]byte, acct account, ok bool) {
	now := time.Now()
	if !ok {
		if len(a.failed) >= maxCacheItems {
			for k, until := range a.failed {
				if now.After(until) {
					delete(a.failed, k)
				}
			}
			if len(a.failed) >= maxCacheItems {
				return
			}
		}
		a.failed[id] = now.Add(failTTL)
		return
	}
	verified.Lock()
	defer verified.Unlock()
	if len(verified.m) >= maxCacheItems {
		for k, e := range verified.m {
			if now.After(e.expires) {
				delete(verified.m, k)
			}
		}
		if len(verified.m) >= maxCacheItems {
			return
		}
	}
	verified.m[id] = verifiedEntry{acct: acct, expires: now.Add(okTTL)}
}
