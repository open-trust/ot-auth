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
)

// Verify 验证请求者身份，如果验证失败，则返回 401 的 gear.HTTPError
func Verify(ctx *gear.Context) error {
	token := otgo.ExtractTokenFromHeader(ctx.Req.Header)
	if token == "" {
		return gear.ErrUnauthorized.WithMsg("invalid authorization token")
	}

	vid, err := conf.OT.ParseOTVID(ctx, token)
	if err != nil {
		return gear.ErrUnauthorized.From(err)
	}
	if conf.SubjectType(vid.ID) == 1 {
		return gear.ErrForbidden.WithMsgf("subject should be one of service, but got %s", vid.ID.String())
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
