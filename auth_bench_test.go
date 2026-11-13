package networkrelay

import "testing"

// Provisioning a fast-only configuration should not perform a discarded
// Argon2 hash. Mixed configurations still need the existing slow dummy hash.
func BenchmarkAuthenticatorProvision(b *testing.B) {
	fast, err := HashGeneratedSecret(RandomPassword())
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		hash string
	}{
		{name: "fast", hash: fast},
		{name: "slow", hash: testHash},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := newAuthenticator([]User{{Name: "device", PasswordHash: tc.hash}}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
