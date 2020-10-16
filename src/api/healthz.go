package api

import (
	"github.com/open-trust/ot-auth/src/bll"
	"github.com/teambition/gear"
)

// Healthz ..
type Healthz struct {
	blls *bll.Blls
}

// Get ..
func (a *Healthz) Get(ctx *gear.Context) error {
	h, err := a.blls.Models.Model.CheckHealth(ctx)
	if err != nil {
		return err
	}
	return ctx.OkJSON(h)
}
