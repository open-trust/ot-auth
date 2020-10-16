package bll

import (
	"github.com/open-trust/ot-auth/src/model"
	"github.com/open-trust/ot-auth/src/util"
)

func init() {
	util.DigProvide(NewBlls)
}

// Blls ...
type Blls struct {
	Models       *model.Models
	OTVID        *OTVID
	Federation   *Federation
	Registration *Registration
}

// NewBlls ...
func NewBlls(models *model.Models) *Blls {
	return &Blls{
		Models:       models,
		OTVID:        &OTVID{models},
		Federation:   &Federation{models},
		Registration: &Registration{models},
	}
}
