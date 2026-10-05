package networkrelay

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestProfileListsKeepRoutesAfterLongComments(t *testing.T) {
	want := []string{"first.example", "last.example"}
	domains := "first.example\n#" + strings.Repeat("x", 65<<10) + "\nlast.example\n"
	if got := parseDomainList(domains); !slices.Equal(got, want) {
		t.Fatalf("domain routes after long comment: %v", got)
	}
	gfw := "[AutoProxy 0.2.9]\n||first.example\n!" + strings.Repeat("x", (1<<20)+1) + "\n||last.example\n"
	if got, _ := extractGFWList(gfw); !slices.Equal(got, want) {
		t.Fatalf("GFW routes after long comment: %v", got)
	}
}

type failingProfileListReader struct{}

func (failingProfileListReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestProfileListReadBounds(t *testing.T) {
	limit := bytes.Repeat([]byte{' '}, maxProfileListSize)
	if got, err := readProfileList(bytes.NewReader(limit)); err != nil || len(got) != len(limit) {
		t.Fatalf("exact limit: %d bytes, %v", len(got), err)
	}
	if got, err := readProfileList(io.MultiReader(bytes.NewReader(limit), strings.NewReader("x"))); err == nil || got != nil {
		t.Fatalf("oversized list accepted: %d bytes, %v", len(got), err)
	}
	if got, err := readProfileList(io.MultiReader(strings.NewReader("first.example\n"), failingProfileListReader{})); !errors.Is(err, io.ErrUnexpectedEOF) || got != nil {
		t.Fatalf("incomplete list accepted: %q, %v", got, err)
	}
}

type profileListTransport func(*http.Request) (*http.Response, error)

func (f profileListTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGFWDownloadRejectsOversizedBody(t *testing.T) {
	// A valid-looking prefix used to pass the 16 MiB LimitReader even
	// though the response contained additional rules beyond that prefix.
	body := io.MultiReader(strings.NewReader("[AutoProxy]\n||first.example\n!"),
		io.LimitReader(neverEnding{}, maxProfileListSize), strings.NewReader("\n||last.example\n"))
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: profileListTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body), Request: r}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = previous })
	if raw, err := loadGFWList(""); err == nil || raw != nil {
		t.Fatalf("oversized download accepted: %d bytes, %v", len(raw), err)
	}
}

func TestProfileCommandPreservesOutputOnListReadFailure(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "oversized.txt")
	if err := os.WriteFile(list, bytes.Repeat([]byte{'x'}, maxProfileListSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "existing.mobileconfig")
	const original = "existing managed profile"
	for _, flag := range []string{"--domains-file", "--gfwlist-file"} {
		t.Run(flag, func(t *testing.T) {
			if err := os.WriteFile(output, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := profileCommand()
			cmd.SetArgs([]string{"--host", "relay.example.com", "--user", "iphone", "--password", "secret",
				"--match-domain", "valid.example", flag, list, "-o", output})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "16 MiB") {
				t.Fatalf("oversized list did not fail before writing: %v", err)
			}
			if got, err := os.ReadFile(output); err != nil || string(got) != original {
				t.Fatalf("existing profile changed: %q, %v", got, err)
			}
		})
	}
}
