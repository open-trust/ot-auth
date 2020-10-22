package api

import (
	"fmt"
	"time"

	"github.com/open-trust/ot-auth/src/bll"
	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/logging"
	"github.com/open-trust/ot-auth/src/middleware"
	"github.com/open-trust/ot-auth/src/service/ac"
	"github.com/open-trust/ot-auth/src/tpl"
	"github.com/open-trust/ot-auth/src/util"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

// OTVID ..
type OTVID struct {
	blls *bll.Blls
}

// Sign ..
func (a *OTVID) Sign(ctx *gear.Context) error {
	// 读取并验证请求数据
	input := &tpl.SignInput{}
	if err := ctx.ParseBody(input); err != nil {
		return err
	}

	token := otgo.ExtractTokenFromHeader(ctx.Req.Header)
	if token == "" {
		return gear.ErrUnauthorized.WithMsg("invalid authorization token")
	}

	// 获取请求主体自己签发的的 OTVID
	vid, signInfo, err := a.blls.OTVID.VerifySelf(ctx, token)
	if err != nil {
		return err
	}
	logging.AccessLogger.SetTo(ctx, "subject", vid.ID.String())
	logging.AccessLogger.SetTo(ctx, "signSubject", input.Subject.String())
	logging.AccessLogger.SetTo(ctx, "signAudience", input.Audience.String())
	subVid := &otgo.OTVID{
		ID:        input.Subject,
		Issuer:    conf.OT.OTID,
		Audience:  input.Audience,
		Expiry:    time.Unix(input.Expiry, 0),
		ReleaseID: input.ReleaseID,
		Claims:    input.Claims,
	}

	var res *tpl.SignPayload
	if vid.ID.IsDomainID() {
		if !input.Audience.MemberOf(conf.OT.TrustDomain) {
			return gear.ErrBadRequest.WithMsgf("%s is not member of %s", input.Audience.String(), conf.OT.TrustDomain.String())
		}
		if signInfo.Status < 1 {
			return gear.ErrForbidden.WithMsgf("%s is not allowed to sign OTVID", signInfo.ID.String())
		}
		if !util.StringsHas(signInfo.AllowedList, func(pattern string) bool {
			return ac.MatchPattern(subVid.ID.Subject(), pattern)
		}) {
			return gear.ErrForbidden.WithMsgf("sign OTVID for %s is not allowed", subVid.ID.String())
		}
		res, err = a.blls.OTVID.Sign(ctx, subVid)
	} else {

		if !vid.ID.Equal(input.Subject) {
			// 当请求主体不是信任域主体并且是代理其它请求主体 sub 申请签发 OTVID，则必须提供目标 sub 的自签发 OTVID
			_, signInfo, err = a.blls.OTVID.VerifySelf(ctx, input.ForwardedOTVID)
			if err != nil {
				return err
			}
		}

		// 当请求主体不是信任域主体时，用内部 release ID（不信任外部输入值）
		subVid.ReleaseID = signInfo.ReleaseID
		if !input.Audience.MemberOf(conf.OT.TrustDomain) {
			res, err = a.blls.OTVID.SignFromFederation(ctx, subVid)
		} else {
			res, err = a.blls.OTVID.Sign(ctx, subVid)
		}
	}

	if err != nil {
		return err
	}
	return ctx.OkJSON(tpl.SuccessResponseType{Result: res})
}

// Verify ..
func (a *OTVID) Verify(ctx *gear.Context) error {
	// 读取并验证请求数据
	input := &tpl.VerifyInput{}
	if err := ctx.ParseBody(input); err != nil {
		return err
	}

	// 获取经过验证的请求主体的 OTVID
	_, err := middleware.VidFromCtx(ctx)
	if err != nil {
		return err
	}

	// 本接口无需验证请求主体的权限
	vid, err := conf.OT.ParseOTVID(ctx, input.OTVID, input.Audience)
	if err != nil {
		// 解析或验证错误，错误信息以 200 响应
		res := gear.ToErrorResponse(err)
		res.Error.Code = 0
		return ctx.OkJSON(res)
	}
	ok, err := a.blls.Registration.CheckStatus(ctx, vid.ID, vid.ReleaseID)
	if !ok && err == nil {
		err = fmt.Errorf("OTVID %s has become invalid", vid.ID.String())
	}
	jwt, _ := vid.ToJWT()
	if err != nil {
		res := gear.ToErrorResponse(err)
		res.Error.Code = 0
		res.Error.Data = jwt
		return ctx.OkJSON(res)
	}
	return ctx.OkJSON(tpl.SuccessResponseType{Result: jwt})
}
