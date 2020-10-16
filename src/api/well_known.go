package api

import (
	"fmt"

	"github.com/open-trust/ot-auth/src/bll"
	"github.com/open-trust/ot-auth/src/conf"
	"github.com/teambition/gear"
)

// WellKnown ..
type WellKnown struct {
	blls *bll.Blls
}

// OpenTrustConfiguration served as `GET /.well-known/open-trust-configuration`
func (a *WellKnown) OpenTrustConfiguration(ctx *gear.Context) error {
	ctx.SetHeader(gear.HeaderCacheControl, fmt.Sprintf("max-age=%d", conf.Config.OpenTrust.KeysRefreshHint))
	return ctx.OkJSON(map[string]interface{}{
		"otid":             conf.OT.OTID,
		"keys":             conf.OT.PublicKeys.Keys,
		"userTypes":        conf.Config.OpenTrust.UserTypes,
		"serviceTypes":     conf.Config.OpenTrust.ServiceTypes,
		"serviceEndpoints": conf.Config.ServiceEndpoints,
		"keysRefreshHint":  conf.Config.OpenTrust.KeysRefreshHint,
	})
}
