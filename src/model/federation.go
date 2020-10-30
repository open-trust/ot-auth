package model

import (
	"context"

	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

// Federation ...
type Federation struct {
	*Model
}

// GetVerificationInfo ...
func (m *Federation) GetVerificationInfo(ctx context.Context, otid otgo.OTID, includeAllowed bool) (*VerificationInfo, error) {
	payload, err := m.Model.GetFederationVerificationInfo(ctx, otid.TrustDomain().String(), includeAllowed)
	if err != nil {
		return nil, err
	}
	doc := payload.GetDomainFederation
	if doc == nil {
		return nil, gear.ErrNotFound.WithMsgf("%s not found", otid.String())
	}

	return &VerificationInfo{ID: otid, Status: doc.Status, AllowedList: doc.AllowedList}, nil
}
