package ac

import (
	"strings"

	"github.com/open-trust/ot-auth/src/conf"
)

func init() {
	// 初始化 OT-Auth 自身作为可信主体的默认权限
	globalPM.Set(conf.OT.OTID.String(), Permission{
		Resource:   string(ResRegistryAll),
		Operations: []string{string(OpGet), string(OpCreate)},
		Extensions: []string{EkCreateRegistry.V("*"), EkGetRegistryBundles.V("*")},
	})
	// 初始化 OT-Auth 以外的其它可信主体的默认权限
	globalPM.Set(conf.OT.OTID.String()+":*", Permission{
		Resource:   string(ResRegistry),
		Operations: []string{string(OpGet)},
	})

	if conf.AppEnv == "testing" {
		globalPM.Set(conf.OT.OTID.String(), Permission{
			Resource:   string(ResAll),
			Operations: []string{string(OpAll)},
			Extensions: []string{EkCreateRegistry.V("*"), EkGetRegistryBundles.V("*"), EkCreateRegistryBundle.V("*")},
		})
	}
}

var globalPM = make(PermissionsManager)

// Operation ...
type Operation string

const (
	// OpAll ...
	OpAll Operation = "*"
	// OpGet ...
	OpGet Operation = "get"
	// OpList ...
	OpList Operation = "list"
	// OpCreate ...
	OpCreate Operation = "create"
	// OpUpdate ...
	OpUpdate Operation = "update"
	// OpDelete ...
	OpDelete Operation = "delete"
)

// Resource ...
type Resource string

const (
	// ResAll ...
	ResAll Resource = "*"
	// ResFederation ...
	ResFederation Resource = "federation"
	// ResRegistryAll ...
	ResRegistryAll Resource = "registry*"
	// ResRegistry ...
	ResRegistry Resource = "registry"
	// ResRegistryBundle ...
	ResRegistryBundle Resource = "registry.bundle"
	// ResRegistryPermission ...
	ResRegistryPermission Resource = "registry.permission"
)

// ExtensionKey ...
type ExtensionKey string

// V ...
func (e ExtensionKey) V(value string) string {
	return string(e) + value
}

const (
	// EkCreateRegistry ...
	EkCreateRegistry ExtensionKey = "createRegistryPattern:"

	// EkCreateRegistryBundle ...
	EkCreateRegistryBundle ExtensionKey = "createRegistryBundlePattern:"

	// EkGetRegistryBundles ...
	EkGetRegistryBundles ExtensionKey = "getRegistryBundlesPattern:"

	// EkGetRegistryPermissions ...
	EkGetRegistryPermissions ExtensionKey = "getRegistryPermissionsPattern:"
)

// Permission ...
type Permission struct {
	Resource   string
	Operations []string
	Extensions []string
}

// Match ...
func (p Permission) Match(resource, operation string) bool {
	if MatchPattern(resource, p.Resource) {
		for _, op := range p.Operations {
			if op == "*" || op == operation {
				return true
			}
		}
	}
	return false
}

// Permissions ...
type Permissions []Permission

// FindExtensionValues ...
func (ps Permissions) FindExtensionValues(key ExtensionKey) []string {
	res := make([]string, 0)
	pattern := string(key)
	for _, p := range ps {
		for _, s := range p.Extensions {
			if strings.HasPrefix(s, pattern) {
				res = append(res, s[len(pattern):])
			}
		}
	}
	return res
}

// Find ...
func (ps Permissions) Find(resource, operation string) Permissions {
	res := make([]Permission, 0)
	for _, p := range ps {
		if p.Match(resource, operation) {
			res = append(res, p)
		}
	}
	return res
}

// PermissionsManager ...
type PermissionsManager map[string]Permissions

// Set ...
func (pm PermissionsManager) Set(otidPattern string, p Permission) {
	pm[otidPattern] = Permissions{p}
}

// Add ...
func (pm PermissionsManager) Add(otidPattern string, p Permission) {
	if _, ok := pm[otidPattern]; !ok {
		pm[otidPattern] = Permissions{p}
	} else {
		pm[otidPattern] = append(pm[otidPattern], p)
	}
}

// Find ...
func (pm PermissionsManager) Find(otid, resource, operation string) Permissions {
	res := make([]Permission, 0)
	for key, ps := range pm {
		if MatchPattern(otid, key) {
			res = append(res, ps.Find(resource, operation)...)
		}
	}
	return res
}

// MatchPattern ...
func MatchPattern(s, pattern string) bool {
	if pattern == "" {
		return false
	} else if pattern == "*" || s == pattern {
		return true
	} else if pattern[len(pattern)-1] == '*' {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return false
}
