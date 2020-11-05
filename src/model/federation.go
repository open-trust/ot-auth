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
	vars := map[string]string{"$domain": otid.TrustDomain().String()}
	q := `query q($domain: string) {
		result(func: eq(domain: $domain)) {
			status
		}
	}
	`
	if includeAllowed {
		q = `query q($domain: string) {
			result(func: eq(domain: $domain)) {
				status
				allowedList
			}
		}
		`
	}
	res := make([]*VerificationInfo, 0)
	out := &otgo.Response{Result: &res}
	err := m.Model.Query(ctx, q, vars, out)
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, gear.ErrNotFound.WithMsgf("%s not found", otid.String())
	}
	res[0].ID = otid
	return res[0], nil
}
