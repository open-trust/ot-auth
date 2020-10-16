package model

import (
	"context"

	otgo "github.com/open-trust/ot-go-lib"
)

// Federation ...
type Federation struct {
	*Model
}

// GetVerificationInfo ...
func (m *Federation) GetVerificationInfo(ctx context.Context, otid otgo.OTID, includeKeys, includeAllowed, includeEndpoints bool) (*VerificationInfo, error) {
	payload, err := m.Model.GetFederationVerificationInfo(ctx, otid.TrustDomain().String(), includeKeys, includeAllowed, includeEndpoints)
	if err != nil {
		return nil, err
	}
	doc := payload.GetDomainFederation
	return &VerificationInfo{ID: otid, Status: doc.Status, Keys: doc.Keys,
		AllowedList: doc.AllowedList, ServiceEndpoints: doc.ServiceEndpoints}, nil
}
