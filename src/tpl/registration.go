package tpl

import (
	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/util"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

// OTIDURL ...
type OTIDURL struct {
	OTID otgo.OTID `param:"otid"`
}

// Validate ...
func (t *OTIDURL) Validate() error {
	// OTID UnmarshalText method will validate
	if !t.OTID.MemberOf(conf.OT.TrustDomain) {
		return gear.ErrBadRequest.WithMsg("OTID's trust domain not support")
	}
	return nil
}

// RegistryInput ...
type RegistryInput struct {
	SubjectID        string   `json:"subjectId"`
	SubjectType      string   `json:"subjectType"`
	Description      string   `json:"description"`
	Keys             []string `json:"keys"`
	ServiceEndpoints []string `json:"serviceEndpoints"`
	OTID             otgo.OTID
}

// Validate 实现 gear.BodyTemplate
func (t *RegistryInput) Validate() error {
	if t.SubjectID == "" {
		return gear.ErrBadRequest.WithMsgf("subjectId required")
	}
	t.OTID = conf.OT.TrustDomain.NewOTID(t.SubjectType, t.SubjectID)
	if err := t.OTID.Validate(); err != nil {
		return err
	}
	if conf.SubjectType(t.OTID) == 0 {
		return gear.ErrBadRequest.WithMsgf("subjectType %s not support", t.SubjectType)
	}
	if t.ServiceEndpoints == nil {
		t.ServiceEndpoints = []string{}
	}
	if l := len(t.ServiceEndpoints); l > 64 {
		return gear.ErrBadRequest.WithMsgf("too many serviceEndpoints (> %d)", l)
	}
	if !util.CheckServiceEndpoints(t.ServiceEndpoints...) {
		return gear.ErrBadRequest.WithMsgf("invalid serviceEndpoints")
	}

	ks, err := otgo.ParseSet(t.Keys...)
	if err != nil {
		return err
	}
	if len(otgo.LookupPublicKeys(ks).Keys) != len(t.Keys) {
		return gear.ErrBadRequest.WithMsgf("public keys required")
	}
	if len(ks.Keys) > 5 {
		return gear.ErrBadRequest.WithMsgf("too many public keys")
	}
	if len(t.Description) > 1024 {
		return gear.ErrBadRequest.WithMsgf("description size too large")
	}
	return nil
}

// AddRegistriesInput ...
type AddRegistriesInput struct {
	*RegistryInput
	Registries []*RegistryInput `json:"registries"`
}

// Validate 实现 gear.BodyTemplate
func (t *AddRegistriesInput) Validate() error {
	if t.RegistryInput != nil {
		if err := t.RegistryInput.Validate(); err != nil {
			return err
		}
	}
	for _, ele := range t.Registries {
		if ele == nil {
			return gear.ErrBadRequest.WithMsgf("invalid input for registries")
		}
		if err := ele.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// RegistryPayload ...
type RegistryPayload struct {
	OTID             *otgo.OTID    `json:"otid"`
	Status           int           `json:"status"`
	SubjectID        string        `json:"subjectId,omitempty"`
	SubjectType      string        `json:"subjectType,omitempty"`
	Description      *string       `json:"description,omitempty"`
	Keys             *[]string     `json:"keys,omitempty"`
	CreatedAt        *int64        `json:"createdAt,omitempty"`
	UpdatedAt        *int64        `json:"updatedAt,omitempty"`
	KeysUpdatedAt    *int64        `json:"keysUpdatedAt,omitempty"`
	ServiceEndpoints *[]string     `json:"serviceEndpoints,omitempty"`
	Bundles          *[]Bundle     `json:"bundles,omitempty"`
	Permissions      *[]Permission `json:"permissions,omitempty"`
}

// Bundle ...
type Bundle struct {
	OTID      *otgo.OTID `json:"otid,omitempty"`
	Provider  *otgo.OTID `json:"provider,omitempty"`
	BundleID  string     `json:"bundleId"`
	Extension string     `json:"extension"`
}

// Permission ...
type Permission struct {
	Resource   string   `json:"resource"`
	Operations []string `json:"operations"`
	Extensions []string `json:"extensions"`
}

// UpdateUsersBundleInput ...
type UpdateUsersBundleInput struct {
	Provider *otgo.OTID `json:"provider,omitempty"`
	Bundles  []*struct {
		OTID      otgo.OTID `json:"otid"`
		BundleID  string    `json:"bundleId"`
		Extension string    `json:"extension"`
	} `json:"bundles"`
}

// Validate 实现 gear.BodyTemplate
func (t *UpdateUsersBundleInput) Validate() error {
	if t.Provider != nil && conf.SubjectType(*t.Provider) != 2 {
		return gear.ErrBadRequest.WithMsgf("provider should be one of service type, but got %s", t.Provider.Type())
	}

	for _, ele := range t.Bundles {
		if ele == nil {
			return gear.ErrBadRequest.WithMsgf("invalid input for bundles")
		}

		if conf.SubjectType(ele.OTID) != 1 {
			return gear.ErrBadRequest.WithMsgf("should be one of user types")
		}

		l := len(ele.BundleID)
		if l == 0 {
			return gear.ErrBadRequest.WithMsg("bundleId required")
		}
		if l > 64 {
			return gear.ErrBadRequest.WithMsgf("bundleId is too long (> %d)", l)
		}
		if l = len(ele.Extension); l > 256 {
			return gear.ErrBadRequest.WithMsgf("extension is too long (> %d)", l)
		}
	}
	return nil
}
