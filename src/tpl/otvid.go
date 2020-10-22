package tpl

import (
	"time"

	"github.com/open-trust/ot-auth/src/conf"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

// VerifyInput ...
type VerifyInput struct {
	Audience otgo.OTID `json:"aud"`
	OTVID    string    `json:"otvid"`
}

// Validate ...
func (t *VerifyInput) Validate() error {
	// OTID UnmarshalText method will validate
	if !t.Audience.MemberOf(conf.OT.TrustDomain) {
		return gear.ErrBadRequest.WithMsgf("aud OTID is not a member of %s", conf.OT.TrustDomain)
	}
	return nil
}

// SignInput ...
type SignInput struct {
	Subject        otgo.OTID              `json:"sub"` // 申请签发 OTVID 的 sub，可以是联盟信任域的 sub
	Audience       otgo.OTID              `json:"aud"` // 申请签发 OTVID 的 aud，可以是联盟信任域的 aud
	Expiry         int64                  `json:"exp"`
	ReleaseID      string                 `json:"rid"`
	Claims         map[string]interface{} `json:"claims"`         // 需要包含的其它签发数据
	ForwardedOTVID string                 `json:"forwardedOtvid"` // 请求主体与 sub 不一致则是代理申请，且请求主体不是联盟域，需要 sub 的自签发 OTVID
}

// Validate ...
func (t *SignInput) Validate() error {
	if t.Expiry <= 0 {
		t.Expiry = time.Now().Add(10 * time.Minute).Unix()
	}
	if t.Expiry > time.Now().AddDate(1, 0, 1).Unix() {
		return gear.ErrBadRequest.WithMsgf("expiry time should not be after 1 year")
	}
	return nil
}

// SignPayload ...
type SignPayload struct {
	Issuer otgo.OTID `json:"iss"`
	OTVID  string    `json:"otvid"`
	Expiry int64     `json:"exp"`
}
