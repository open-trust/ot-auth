package bll

import (
	"context"

	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/model"
	"github.com/open-trust/ot-auth/src/service/federation"
	"github.com/open-trust/ot-auth/src/tpl"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

// OTVID ...
type OTVID struct {
	ms *model.Models
}

// VerifySelf ...
func (b *OTVID) VerifySelf(ctx context.Context, token string) (*otgo.OTVID, *model.VerificationInfo, error) {
	vid, err := otgo.ParseOTVIDInsecure(token)
	if err != nil {
		return nil, nil, gear.ErrUnauthorized.From(err)
	}
	var info *model.VerificationInfo
	if vid.ID.IsDomainID() {
		info, err = b.ms.Federation.GetVerificationInfo(ctx, vid.ID, true)
	} else {
		info, err = b.ms.Registration.GetVerificationInfo(ctx, vid.ID, true, false)
	}
	if err != nil {
		return nil, nil, gear.ErrUnauthorized.WithMsgf("%s unknown: %s", vid.ID.String(), err.Error())
	}
	if info.Status < 0 {
		return nil, nil, gear.ErrUnauthorized.WithMsgf("%s has been forbidden", vid.ID.String())
	}

	if vid.ID.IsDomainID() {
		cfg, err := conf.OT.OTClient.Domain(vid.ID.TrustDomain()).Resolve(ctx)
		if err == nil {
			err = vid.Verify(cfg.JWKSet, vid.ID, conf.OT.OTID)
		}
	} else {
		ks, err := otgo.ParseSet(info.Keys...)
		if err == nil {
			err = vid.Verify(ks, vid.ID, conf.OT.OTID)
		}
	}

	if err != nil {
		return nil, nil, gear.ErrUnauthorized.From(err)
	}
	return vid, info, nil
}

// Sign ...
func (b *OTVID) Sign(ctx context.Context, subVid *otgo.OTVID) (*tpl.SignPayload, error) {
	signingKey, err := otgo.LookupSigningKey(conf.OT.PrivateKeys)
	if err != nil {
		return nil, err
	}
	token, err := subVid.Sign(signingKey)
	if err != nil {
		return nil, gear.ErrBadRequest.From(err)
	}
	res := &tpl.SignPayload{
		Issuer:   conf.OT.OTID,
		Audience: subVid.Audience,
		Expiry:   subVid.Expiry.Unix(),
		OTVID:    token,
	}

	if subVid.Audience.IsDomainID() {
		res.ServiceEndpoints = conf.Config.ServiceEndpoints
		return res, nil
	}

	info, err := b.ms.Registration.GetVerificationInfo(ctx, subVid.Audience, false, true)
	if err != nil {
		return nil, gear.ErrBadRequest.From(err)
	}
	if info.Status < 0 {
		return nil, gear.ErrBadRequest.WithMsgf("%s has been forbidden", subVid.Audience.String())
	}

	if conf.SubjectType(subVid.Audience) == 2 {
		res.ServiceEndpoints = info.ServiceEndpoints
	}
	return res, nil
}

// SignFromFederation ...
func (b *OTVID) SignFromFederation(ctx context.Context, subVid *otgo.OTVID) (*tpl.SignPayload, error) {
	trustDomain := subVid.Audience.TrustDomain()
	info, err := b.ms.Federation.GetVerificationInfo(ctx, trustDomain.OTID(), false)
	if err != nil {
		return nil, gear.ErrBadRequest.WithMsgf("%s unknown: %s", trustDomain.OTID().String(), err.Error())
	}
	if info.Status < 0 {
		return nil, gear.ErrBadRequest.WithMsgf("%s has been forbidden", trustDomain.String())
	}

	input := tpl.SignInput{
		Subject:   subVid.ID,
		Audience:  subVid.Audience,
		Expiry:    subVid.Expiry.Unix(),
		ReleaseID: subVid.ReleaseID,
		Claims:    subVid.Claims,
	}
	res := &tpl.SignPayload{}
	output := &tpl.SuccessResponseType{Result: res}
	if err = federation.Sign(ctx, trustDomain, input, output); err != nil {
		return nil, err
	}
	return res, nil
}
