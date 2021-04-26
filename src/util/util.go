package util

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/crypto/blake2b"

	otgo "github.com/open-trust/ot-go-lib"
)

// SubjectUK generate a composite unique index value for OTUser or OTService.
func SubjectUK(otid otgo.OTID) string {
	return hashBase64(otid.Type(), otid.ID())
}

// UserBundleUK generate a composite unique index value for OTUserBundle.
func UserBundleUK(provider otgo.OTID, bundleID string) string {
	return hashBase64(provider.Type(), provider.ID(), bundleID)
}

// ServicePermissionUK generate a composite unique index value for OTServicePermission.
func ServicePermissionUK(service otgo.OTID, resource string) string {
	return hashBase64(service.Type(), service.ID(), resource)
}

func hashBase64(ss ...string) string {
	var b bytes.Buffer
	for _, s := range ss {
		b.WriteString(s)
	}
	h := blake2b.Sum256(b.Bytes())
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ReleaseID generate a release ID for user registry
func ReleaseID() string {
	return strconv.FormatInt(UnixMS(), 36)
}

// UnixMS returns a Unix time, the number of milliseconds elapsed since January 1, 1970 UTC.
func UnixMS(ts ...time.Time) int64 {
	var t time.Time
	if len(ts) == 0 {
		t = time.Now()
	} else {
		t = ts[0]
	}
	t = t.UTC().Truncate(time.Millisecond)
	return t.Unix()*1000 + int64(t.Nanosecond()/1e6)
}

// StringsHas ...
func StringsHas(ss []string, filter func(s string) bool) bool {
	for _, s := range ss {
		if filter(s) {
			return true
		}
	}
	return false
}

// CheckServiceEndpoints ...
func CheckServiceEndpoints(ss ...string) bool {
	for _, s := range ss {
		if len(s) > 128 {
			return false
		}
		if _, err := url.ParseRequestURI(s); err != nil {
			return false
		}
	}
	return true
}
