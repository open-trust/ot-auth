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

type permissionOut struct {
	Status     int      `json:"status"`
	Resource   string   `json:"resource"`
	Operations []string `json:"operations"`
	Extensions []string `json:"extensions"`
}

// FindPermission ...
func (s *Service) FindPermission(ctx context.Context, subject otgo.OTID, resource Resource, operation Operation) (*Permission, error) {
	vars := map[string]string{"$uk": util.ServicePermissionUK(subject, string(resource))}
	q := `query q($uk: string) {
		result(func: eq(permissionUK: $uk)) @cascade @normalize {
			resource: resource
			operations: operations
			extensions: extensions
			serviceRegistry {
				status: status
			}
		}
	}
	`

	ps := new(permissionOut)
	out := &otgo.Response{Result: ps}
	err := s.Query(ctx, q, vars, out)
	if err != nil {
		return nil, err
	}
	if ps.Status < 0 {
		return nil, fmt.Errorf("%s had been forbidden", subject.String())
	}
	p := Permission{Resource: ps.Resource, Operations: ps.Operations, Extensions: ps.Extensions}
	if !p.Match(string(resource), string(operation)) {
		return nil, fmt.Errorf("no permissions found")
	}
	return &p, nil
}

// FindPermissions ...
func FindPermissions(ctx context.Context, subject otgo.OTID, resource Resource, operation Operation) (Permissions, error) {
	var err error
	ps := globalPM.Find(subject.String(), string(resource), string(operation))
	if len(ps) == 0 {
		var p *Permission
		p, err = as.FindPermission(ctx, subject, resource, operation)
		if err == nil {
			ps = append(ps, *p)
		}
	}
	if err != nil {
		return nil, gear.ErrForbidden.WithMsgf("find permissions error: %s", err.Error())
	}
	if len(ps) == 0 {
		return nil, gear.ErrForbidden.WithMsgf("%s has no permissions for %s %s", subject.String(), operation, resource)
	}
	return ps, nil
}
