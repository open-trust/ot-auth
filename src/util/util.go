package util

import (
	"crypto/sha1"
	"encoding/base64"
	"net/url"
	"strconv"
	"time"

	otgo "github.com/open-trust/ot-go-lib"
)

// SubjectUK generate a composite unique index value for UserRegistry or ServiceRegistry.
func SubjectUK(otid otgo.OTID) string {
	return sha1Base64(otid.Type(), otid.ID())
}

// UserBundleUK generate a composite unique index value for UserRegistryBundle.
func UserBundleUK(otid otgo.OTID, bundleID string) string {
	return sha1Base64(otid.Type(), otid.ID(), bundleID)
}

// ServicePermissionUK generate a composite unique index value for ServiceRegistryPermission.
func ServicePermissionUK(otid otgo.OTID, resource string) string {
	return sha1Base64(otid.Type(), otid.ID(), resource)
}

func sha1Base64(ss ...string) string {
	h := sha1.New()
	for _, s := range ss {
		h.Write([]byte(s))
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// ReleaseID generate a release ID for user registry
func ReleaseID() string {
	return strconv.FormatInt(time.Now().Unix(), 36)
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
		if len(s) > 100 {
			return false
		}
		if _, err := url.ParseRequestURI(s); err != nil {
			return false
		}
	}
	return true
}
