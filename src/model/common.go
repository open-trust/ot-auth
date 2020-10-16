package model

import (
	"github.com/open-trust/ot-auth/src/service/dgraph"
	"github.com/open-trust/ot-auth/src/util"
	otgo "github.com/open-trust/ot-go-lib"
)

func init() {
	util.DigProvide(NewModels)
}

// Model ...
type Model struct {
	*dgraph.Dgraph
}

// Models ...
type Models struct {
	Model        *Model
	Federation   *Federation
	Registration *Registration
}

// NewModels ...
func NewModels(dg *dgraph.Dgraph) *Models {
	m := &Model{dg}
	return &Models{
		Model:        m,
		Federation:   &Federation{m},
		Registration: &Registration{m},
	}
}

// VerificationInfo ...
type VerificationInfo struct {
	ID               otgo.OTID
	Status           int
	ReleaseID        string
	Keys             []string
	AllowedList      []string
	ServiceEndpoints []string
}
