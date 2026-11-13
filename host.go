package networkrelay

import "golang.org/x/net/http/httpguts"

// The same grammar is used before HTTP/2 and HTTP/3 request dispatch.
func validHostField(value string) bool { return httpguts.ValidHostField(value) }
func validAuthority(value string, allowUserinfo bool) bool {
	return httpguts.ValidAuthority(value, allowUserinfo)
}
