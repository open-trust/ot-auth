package federation

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/open-trust/ot-auth/src/conf"
	otgo "github.com/open-trust/ot-go-lib"
)

func init() {
	ua := fmt.Sprintf("Go/%v %s/%s (%s)", runtime.Version(), conf.AppName, conf.AppVersion, conf.OT.OTID.String())
	Cli.OTID = conf.OT.OTID
	Cli.JWKSet = conf.OT.PrivateKeys
	Cli.HTTPClient = otgo.DefaultHTTPClient.WithUA(ua)
}

// Cli ...
var Cli = new(Client)

// Client ...
type Client struct {
	*otgo.HTTPClient
	OTID   otgo.OTID
	JWKSet *otgo.JWKSet
}

// Sign ..
func (fc *Client) Sign(ctx context.Context, federationDomain otgo.TrustDomain, serviceEndpoint string, input, output interface{}) error {
	signingKey, err := otgo.LookupSigningKey(fc.JWKSet)
	if err != nil {
		return err
	}

	selfVid := &otgo.OTVID{
		ID:       fc.OTID,
		Issuer:   fc.OTID,
		Audience: federationDomain.OTID(),
		Expiry:   time.Now().Add(time.Minute),
	}
	token, err := selfVid.Sign(signingKey)
	if err != nil {
		return err
	}

	return fc.WithToken(token).Post(ctx, serviceEndpoint+"/sign", input, output)
}
