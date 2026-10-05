package networkrelay

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// A CONNECT authority names its destination, so it cannot equal the relay's
// TLS SNI. Turning off Caddy's Host/SNI guard is appropriate on a proxy listener,
// provided every accepted TLS policy has the same client authentication rules.
// Otherwise an unprotected SNI could bypass a protected site's client auth.
func validateRelayTLS(srv *caddyhttp.Server) error {
	if srv.StrictSNIHost != nil && *srv.StrictSNIHost {
		return fmt.Errorf("network_relay requires strict_sni_host to be false because CONNECT names the destination; use a dedicated relay listener with uniform TLS client authentication and set strict_sni_host insecure_off in the Caddyfile servers block")
	}
	var first []byte
	havePolicy, uniform, clientAuth := false, true, false
	for _, p := range srv.TLSConnPolicies {
		if p.Drop {
			continue
		}
		auth := p.ClientAuthentication
		var encoded []byte
		if auth != nil && auth.Active() {
			clientAuth = true
			var err error
			encoded, err = json.Marshal(auth)
			if err != nil {
				return fmt.Errorf("encoding relay TLS client authentication: %w", err)
			}
		}
		if !havePolicy {
			first, havePolicy = encoded, true
		} else if !bytes.Equal(first, encoded) {
			uniform = false
		}
	}
	if clientAuth && !uniform {
		return fmt.Errorf("network_relay requires the same TLS client authentication configuration on every accepted TLS policy; separate sites with different client authentication onto different listeners")
	}
	return nil
}

// CA providers are provisioned after relay handlers. Identical declarations
// can fetch different effective roots (for example, a remote bundle rotating
// between two reads), so check the completed policies before serving them.
func validateEffectiveRelayTLS(srv *caddyhttp.Server) error {
	var first *tls.Config
	for _, p := range srv.TLSConnPolicies {
		if p.Drop {
			continue
		}
		if p.TLSConfig == nil {
			return fmt.Errorf("network_relay TLS policy is not fully provisioned")
		}
		if first == nil {
			first = p.TLSConfig
		} else if !sameEffectiveTLSClientAuth(first, p.TLSConfig) {
			return fmt.Errorf("network_relay requires the same effective TLS client authentication and CA roots on every accepted TLS policy")
		}
	}
	return nil
}

func sameEffectiveTLSClientAuth(a, b *tls.Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.ClientAuth == b.ClientAuth && a.ClientCAs.Equal(b.ClientCAs)
}

// Provision has already verified that every accepted policy is uniform.
// Capture only client authentication; ACME renewal does not change it.
func relayTLSClientAuth(srv *caddyhttp.Server) ([]byte, error) {
	for _, p := range srv.TLSConnPolicies {
		if p.Drop {
			continue
		}
		if auth := p.ClientAuthentication; auth != nil && auth.Active() {
			return json.Marshal(auth)
		}
		return nil, nil
	}
	return nil, nil
}

// Capture before Caddy loads verifier modules and clears VerifiersRaw. Their
// effective trust may come from files or external sources hidden inside the
// module, so identical declarations do not establish equivalent trust.
func relayTLSHasCustomVerifiers(srv *caddyhttp.Server) bool {
	for _, p := range srv.TLSConnPolicies {
		if !p.Drop && p.ClientAuthentication != nil && len(p.ClientAuthentication.VerifiersRaw) > 0 {
			return true
		}
	}
	return false
}
