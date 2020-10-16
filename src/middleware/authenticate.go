package middleware

import (
	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/logging"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

type contextKey int

const (
	authKey contextKey = iota
	acKey
)

// Verify 验证请求者身份，如果验证失败，则返回 401 的 gear.HTTPError
func Verify(ctx *gear.Context) error {
	token := otgo.ExtractTokenFromHeader(ctx.Req.Header)
	if token == "" {
		return gear.ErrUnauthorized.WithMsg("invalid authorization token")
	}

	vid, err := conf.OT.Verifier.ParseOTVID(token)
	if err != nil {
		return gear.ErrUnauthorized.From(err)
	}

	ctx.SetAny(authKey, vid)
	logging.AccessLogger.SetTo(ctx, "subject", vid.ID.String())
	return nil
}

// VidFromCtx ...
func VidFromCtx(ctx *gear.Context) (*otgo.OTVID, error) {
	val, err := ctx.Any(authKey)
	if err != nil {
		return nil, err
	}
	vid, ok := val.(*otgo.OTVID)
	if !ok {
		return nil, gear.ErrUnauthorized.WithMsg("OTVID not exist")
	}
	return vid, nil
}
