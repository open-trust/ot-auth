package federation

import (
	"context"
	"net/http"
	"time"

	"github.com/open-trust/ot-auth/src/conf"
	otgo "github.com/open-trust/ot-go-lib"
)

// Sign ..
func Sign(ctx context.Context, federationDomain otgo.TrustDomain, input, output interface{}) error {
	signingKey, err := otgo.LookupSigningKey(conf.OT.PrivateKeys)
	if err != nil {
		return err
	}

	selfVid := &otgo.OTVID{
		ID:       conf.OT.OTID,
		Issuer:   conf.OT.OTID,
		Audience: federationDomain.OTID(),
		Expiry:   time.Now().Add(time.Minute),
	}
	selfToken, err := selfVid.Sign(signingKey)
	if err != nil {
		return err
	}
	cfg, err := conf.OT.OTClient.Domain(federationDomain).Resolve(ctx)
	if err != nil {
		return err
	}
	h := otgo.AddTokenToHeader(make(http.Header), selfToken)
	return conf.OT.OTClient.HTTPClient.Do(ctx, "POST", cfg.Endpoint+"/sign", h, input, output)
}
