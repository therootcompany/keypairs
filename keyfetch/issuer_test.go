package keyfetch

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func TestInvalidIssuer(t *testing.T) {
	_, err := NewWhitelist([]string{"somethingorother"})
	if nil == err {
		t.Log("invalid http urls can get through, but that's okay")
	}

	_, err = NewWhitelist([]string{"//example.com/foo"})
	if nil == err {
		t.Fatal(errors.New("semi-bad url got through"))
	}
}

func TestIssuerMatches(t *testing.T) {
	trusted := []string{
		"https://example.com/",
		"http://happy.xyz/abc",
		"foobar.net/def/",
		"https://*.wild.org",
		"https://*.west.mali/verde",
	}

	_, err := NewWhitelist(trusted)
	if nil == err {
		t.Fatal(errors.New("An insecure domain got through!"))
	}

	list, err := NewWhitelist(trusted, true)
	if nil != err {
		t.Fatal(err)
	}

	var iss string
	iss = "https://example.com"
	if !IsTrustedIssuer(iss, list) {
		t.Fatal("A good domain didn't make it:", iss)
	}

	iss = "https://example.com/"
	if !IsTrustedIssuer(iss, list) {
		t.Fatal("A good domain didn't make it:", iss)
	}

	iss = "http://example.com"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}

	iss = "https://example.com/foo"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}

	iss = "http://happy.xyz/abc"
	if !IsTrustedIssuer(iss, list) {
		t.Fatal("A good URL didn't make it:", iss)
	}

	iss = "http://happy.xyz/abc/"
	if !IsTrustedIssuer(iss, list) {
		t.Fatal("A good URL didn't make it:", iss)
	}

	iss = "http://happy.xyz/abc/d"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}

	iss = "http://happy.xyz/abcd"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}

	iss = "https://foobar.net/def"
	if !IsTrustedIssuer(iss, list) {
		t.Fatal("A good URL didn't make it:", iss)
	}

	iss = "https://foobar.net/def/"
	if !IsTrustedIssuer(iss, list) {
		t.Fatal("A good URL didn't make it:", iss)
	}

	iss = "http://foobar.net/def/"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}

	iss = "https://foobar.net/def/e"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}

	iss = "https://foobar.net/defe"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}

	iss = "https://wild.org"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}

	iss = "https://foo.wild.org"
	if !IsTrustedIssuer(iss, list) {
		t.Fatal("A good URL didn't make it:", iss)
	}

	iss = "https://sub.foo.wild.org"
	if !IsTrustedIssuer(iss, list) {
		t.Fatal("A good URL didn't make it:", iss)
	}

	iss = "https://foo.wild.org/cherries"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}

	iss = "https://sub.west.mali/verde/"
	if !IsTrustedIssuer(iss, list) {
		t.Fatal("A good URL didn't make it:", iss)
	}

	iss = "https://sub.west.mali"
	if IsTrustedIssuer(iss, list) {
		t.Fatal("A bad URL slipped past", iss)
	}
}

func TestImplicitIssuer(t *testing.T) {
	var r *http.Request
	var iss string

	r = &http.Request{
		Host: "example.com",
		URL:  &url.URL{Path: "/foo/bar/baz"},
		Header: http.Header(map[string][]string{
			"x-forwarded-host": []string{"example.com"},
		}),
	}
	iss = "https://example.com/foo"
	if !IsTrustedIssuer(iss, nil, r) {
		t.Fatal("A good URL didn't make it:", iss)
	}

	r = &http.Request{
		Host: "example.com",
		URL:  &url.URL{Path: "/"},
		Header: http.Header(map[string][]string{
			"x-forwarded-host":  []string{"example.com"},
			"x-forwarded-proto": []string{"http"},
		}),
	}
	iss = "http://example.com/foo"
	if IsTrustedIssuer(iss, nil, r) {
		t.Fatal("A bad URL slipped past:", iss)
	}

	r = &http.Request{
		Host: "example.com",
		URL:  &url.URL{Path: "/foo"},
		Header: http.Header(map[string][]string{
			"x-forwarded-host": []string{"example.com"},
		}),
	}
	iss = "https://example.com/foo/bar/baz"
	if IsTrustedIssuer(iss, nil, r) {
		t.Fatal("A bad URL slipped past:", iss)
	}

	r = &http.Request{
		Host: "example.com",
		URL:  &url.URL{Path: "/"},
		Header: http.Header(map[string][]string{
			"x-forwarded-proto": []string{"https"},
		}),
	}
	iss = "https://example.com/"
	if !IsTrustedIssuer(iss, nil, r) {
		t.Fatal("A good URL didn't make it:", iss)
	}
}
