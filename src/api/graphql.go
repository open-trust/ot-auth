package api

import (
	"github.com/open-trust/ot-auth/src/bll"
	"github.com/teambition/gear"
)

// GraphQL ..
type GraphQL struct {
	blls *bll.Blls
}

// All is graphql endpoint
func (a *GraphQL) All(ctx *gear.Context) error {
	return gear.ErrNotImplemented.WithMsg("TODO")
}
