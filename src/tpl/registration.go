package tpl

import (
	"time"

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

// AddRegistrationInput ...
type AddRegistrationInput struct {
	SubjectID        string   `json:"subjectId"`
	SubjectType      string   `json:"subjectType"`
	Description      string   `json:"description"`
	Keys             []string `json:"keys"`
	ServiceEndpoints []string `json:"serviceEndpoints"`
	OTID             otgo.OTID
}

// Validate 实现 gear.BodyTemplate
func (t *AddRegistrationInput) Validate() error {
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
	if l := len(t.ServiceEndpoints); l > 100 {
		return gear.ErrBadRequest.WithMsgf("too many serviceEndpoints (> %d)", l)
	}
	ks, err := otgo.ParseKeys(t.Keys...)
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
	if !util.CheckServiceEndpoints(t.ServiceEndpoints...) {
		return gear.ErrBadRequest.WithMsgf("invalid serviceEndpoints")
	}
	if len(t.ServiceEndpoints) > 10 {
		return gear.ErrBadRequest.WithMsgf("too many serviceEndpoints")
	}
	return nil
}

// RegistrationPayload ...
type RegistrationPayload struct {
	OTID             otgo.OTID     `json:"otid"`
	Status           int           `json:"status"`
	SubjectID        string        `json:"subjectId,omitempty"`
	SubjectType      string        `json:"subjectType,omitempty"`
	Description      *string       `json:"description,omitempty"`
	Keys             *[]string     `json:"keys,omitempty"`
	CreatedAt        *time.Time    `json:"createdAt,omitempty"`
	UpdatedAt        *time.Time    `json:"updatedAt,omitempty"`
	KeysUpdatedAt    *time.Time    `json:"keysUpdatedAt,omitempty"`
	ServiceEndpoints *[]string     `json:"serviceEndpoints,omitempty"`
	Bundles          *[]Bundle     `json:"bundles,omitempty"`
	Permissions      *[]Permission `json:"permissions,omitempty"`
}

// Bundle ...
type Bundle struct {
	Provider otgo.OTID `json:"provider"`
	BundleID string    `json:"bundleId"`
}

// Permission ...
type Permission struct {
	Resource   string   `json:"resource"`
	Operations []string `json:"operations"`
	Extensions []string `json:"extensions"`
}
