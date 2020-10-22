package api

import (
	"github.com/open-trust/ot-auth/src/bll"
	"github.com/open-trust/ot-auth/src/util"
)

func init() {
	util.DigProvide(NewAPIs)
}

// APIs ..
type APIs struct {
	Healthz      *Healthz
	WellKnown    *WellKnown
	GraphQL      *GraphQL
	Registration *Registration
	OTVID        *OTVID
}

// NewAPIs ...
func NewAPIs(blls *bll.Blls) *APIs {
	return &APIs{
		GraphQL:      &GraphQL{blls: blls},
		Healthz:      &Healthz{blls: blls},
		WellKnown:    &WellKnown{blls: blls},
		Registration: &Registration{blls: blls},
		OTVID:        &OTVID{blls: blls},
	}
}
