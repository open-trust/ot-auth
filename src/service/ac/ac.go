package ac

import (
	"context"
	"fmt"

	"github.com/open-trust/ot-auth/src/service/dgraph"
	"github.com/open-trust/ot-auth/src/util"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

func init() {
	err := util.DigInvoke(func(dg *dgraph.Dgraph) error {
		*as = Service{dg}
		return nil
	})
	if err != nil {
		panic(err)
	}
}

var as = new(Service)

// Service ...
type Service struct {
	*dgraph.Dgraph
}

// FindPermissions ...
func (s *Service) FindPermissions(ctx context.Context, subject otgo.OTID, resource Resource, operation Operation) (Permissions, error) {
	res, err := s.Dgraph.GetServicePermissions(ctx, util.ServicePermissionUK(subject, string(resource)))
	if err != nil {
		return nil, err
	}
	if res.GetServiceRegistry.Status < 0 {
		return nil, fmt.Errorf("%s had been forbidden", subject.String())
	}
	ps := make([]Permission, 0, len(res.GetServiceRegistry.Permissions))
	for _, v := range res.GetServiceRegistry.Permissions {
		ps = append(ps, Permission{Resource: v.Resource, Operations: v.Operations, Extensions: v.Extensions})
	}
	return ps, nil
}

// FindPermissions ...
func FindPermissions(ctx context.Context, subject otgo.OTID, resource Resource, operation Operation) (Permissions, error) {
	var err error
	ps := globalPM.Find(subject.String(), string(resource), string(operation))
	if len(ps) == 0 {
		ps, err = as.FindPermissions(ctx, subject, resource, operation)
	}
	if err != nil {
		return nil, gear.ErrForbidden.WithMsgf("find permissions error: %s", err.Error())
	}
	if len(ps) == 0 {
		return nil, gear.ErrForbidden.WithMsgf("%s has no permissions for %s %s", subject.String(), operation, resource)
	}
	return ps, nil
}
