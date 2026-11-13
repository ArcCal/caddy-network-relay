package networkrelay

import (
	"bufio"
	"fmt"
	"strings"
	"testing"
)

// RFC 7617 section 2 forbids the RFC 5234 CTL octets, even though Base64 and
// XML could otherwise carry some of them without damaging message framing.
func TestBasicCredentialsRejectControls(t *testing.T) {
	controls := append([]byte{}, byte(127))
	for c := byte(0); c < 32; c++ {
		controls = append(controls, c)
	}
	for _, c := range controls {
		t.Run(fmt.Sprintf("%02x", c), func(t *testing.T) {
			password := "password" + string(c) + "suffix"
			if _, _, ok := parseBasic(BasicAuthorization("device", password)); ok {
				t.Fatal("accepted control in Basic password")
			}
			if _, _, ok := parseBasic(BasicAuthorization("device"+string(c), "password")); ok {
				t.Fatal("accepted control in Basic user ID")
			}
			p := Profile{Host: "relay.test", User: "device", Password: password}
			if _, err := p.Generate(); err == nil {
				t.Fatal("profile emitted a Basic password containing a control")
			}
			if _, err := p.GenerateDDM(); err == nil {
				t.Fatal("DDM emitted a Basic password containing a control")
			}
		})
	}
}

func TestBasicCredentialsPreserveNonControlOctets(t *testing.T) {
	for _, password := range []string{"space and:colon", "caf\u00e9-\U0001f511", "C1-\u0085", "legacy-\xff\x80"} {
		_, got, ok := parseBasic(BasicAuthorization("device", password))
		if !ok || got != password {
			t.Fatalf("valid non-CTL credential altered: %q -> %q, accepted=%v", password, got, ok)
		}
	}
	for _, password := range []string{"space and:colon", "caf\u00e9-\U0001f511", "C1-\u0085"} {
		p := Profile{Host: "relay.test", User: "device", Password: password}
		if _, err := p.Generate(); err != nil {
			t.Fatalf("valid UTF-8 profile password %q: %v", password, err)
		}
		if _, err := p.GenerateDDM(); err != nil {
			t.Fatalf("valid UTF-8 DDM password %q: %v", password, err)
		}
	}
}

func TestPasswdRejectsBasicControls(t *testing.T) {
	old := stdinLines
	defer func() { stdinLines = old }()
	for _, password := range []string{"password\tcontains-tab", "password\x7fcontains-del"} {
		stdinLines = func() *bufio.Reader { return bufio.NewReader(strings.NewReader(password + "\n")) }
		cmd := passwdCommand()
		cmd.SetArgs([]string{"--name", "device", "--stdin"})
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err == nil {
			t.Fatalf("passwd accepted control in %q", password)
		}
	}
}
