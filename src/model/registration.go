package model

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/tpl"
	"github.com/open-trust/ot-auth/src/util"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

// Registration ...
type Registration struct {
	*Model
}

// Add ...
func (m *Registration) Add(ctx context.Context, input *tpl.RegistryInput) (*tpl.RegistryPayload, error) {
	var nq *Nquads
	now := util.UnixMS()
	res := &tpl.RegistryPayload{
		OTID:          &input.OTID,
		SubjectID:     input.OTID.ID(),
		SubjectType:   input.OTID.Type(),
		Description:   &input.Description,
		Keys:          &input.Keys,
		CreatedAt:     &now,
		UpdatedAt:     &now,
		KeysUpdatedAt: &now,
		Status:        0,
	}

	switch conf.SubjectType(input.OTID) {
	case 1:
		nq = &Nquads{
			UKkey: "userUK",
			UKval: util.SubjectUK(input.OTID),
			Type:  "UserRegistry",
			KV: map[string]interface{}{
				"createdAt":     now,
				"updatedAt":     now,
				"subjectId":     input.SubjectID,
				"subjectType":   input.SubjectType,
				"description":   input.Description,
				"keys":          input.Keys,
				"keysUpdatedAt": now,
				"status":        0,
				"releaseId":     util.ReleaseID(),
			},
		}
	case 2:
		res.ServiceEndpoints = &input.ServiceEndpoints
		nq = &Nquads{
			UKkey: "serviceUK",
			UKval: util.SubjectUK(input.OTID),
			Type:  "ServiceRegistry",
			KV: map[string]interface{}{
				"createdAt":        now,
				"updatedAt":        now,
				"subjectId":        input.SubjectID,
				"subjectType":      input.SubjectType,
				"description":      input.Description,
				"keys":             input.Keys,
				"keysUpdatedAt":    now,
				"serviceEndpoints": input.ServiceEndpoints,
				"status":           0,
			},
		}
	default:
		return nil, fmt.Errorf("unknow subject type")
	}

	if err := m.Model.Create(ctx, nq); err != nil {
		return nil, err
	}
	return res, nil
}

// Get ...
func (m *Registration) Get(ctx context.Context, input *tpl.OTIDURL) (*tpl.RegistryPayload, error) {
	var q string
	uk := util.SubjectUK(input.OTID)
	vars := map[string]string{"$uk": uk}

	switch conf.SubjectType(input.OTID) {
	case 1:
		q = `query q($uk: string) {
			result(func: eq(userUK, $uk)) {
				createdAt
				updatedAt
				subjectId
				subjectType
				description
				keys
				keysUpdatedAt
				status
			}
		}
		`
	case 2:
		q = `query q($uk: string) {
			result(func: eq(serviceUK, $uk)) {
				createdAt
				updatedAt
				subjectId
				subjectType
				description
				keys
				keysUpdatedAt
				status
				serviceEndpoints
			}
		}
		`
	default:
		return nil, fmt.Errorf("unknow subject type")
	}

	res := &tpl.RegistryPayload{}
	err := m.Model.Get(ctx, q, vars, res)
	if err != nil {
		return nil, err
	}
	res.OTID = &input.OTID
	return res, nil
}

// GetVerificationInfo ...
func (m *Registration) GetVerificationInfo(ctx context.Context, otid otgo.OTID, includeKeys, includeEndpoints bool) (*VerificationInfo, error) {
	var q string
	uk := util.SubjectUK(otid)
	vars := map[string]string{"$uk": uk}

	switch conf.SubjectType(otid) {
	case 1:
		q = `query q($uk: string) {
			result(func: eq(userUK, $uk)) {
				status
				releaseId
			}
		}
		`
		if includeKeys {
			q = `query q($uk: string) {
				result(func: eq(userUK, $uk)) {
					status
					releaseId
					keys
				}
			}
			`
		}
	case 2:
		q = `query q($uk: string) {
			result(func: eq(serviceUK, $uk)) {
				status
			}
		}
		`
		if includeKeys {
			q = `query q($uk: string) {
				result(func: eq(serviceUK, $uk)) {
					status
					keys
				}
			}
			`
		}
		if includeEndpoints {
			q = `query q($uk: string) {
				result(func: eq(serviceUK, $uk)) {
					status
					serviceEndpoints
				}
			}
			`
		}
		if includeKeys && includeEndpoints {
			q = `query q($uk: string) {
				result(func: eq(serviceUK, $uk)) {
					status
					keys
					serviceEndpoints
				}
			}
			`
		}
	default:
		return nil, fmt.Errorf("unknow subject type")
	}

	res := &VerificationInfo{}
	err := m.Model.Get(ctx, q, vars, res)
	if err != nil {
		return nil, err
	}
	res.ID = otid
	return res, nil
}

// SubjectInfo ...
type SubjectInfo struct {
	OTID   otgo.OTID
	UID    string `json:"uid"`
	Status int    `json:"status"`
}

// AcquireInfos ...
func (m *Registration) AcquireInfos(ctx context.Context, input map[string]otgo.OTID) (map[string]SubjectInfo, error) {
	qs := make([]string, 0, len(input))
	for k, v := range input {
		UKkey := RegistryUKkey(v)
		if UKkey == "" {
			return nil, fmt.Errorf("invalid subject %s for %s", v.String(), k)
		}
		qs = append(qs, fmt.Sprintf(`%s(func: eq(%s, "%s")) {
			uid
			status
		}`, k, UKkey, util.SubjectUK(v)))
	}

	if len(qs) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	q := fmt.Sprintf(`query {
		%s
	}
	`, strings.Join(qs, "\n"))
	out := make(map[string][]*SubjectInfo)
	err := m.Model.Query(ctx, q, nil, &out)
	if err != nil {
		return nil, err
	}
	res := make(map[string]SubjectInfo)
	for k, v := range out {
		if len(v) == 0 {
			return nil, gear.ErrNotFound.WithMsgf("resource not found for %s", k)
		}
		if len(v) > 1 {
			return nil, gear.ErrUnprocessableEntity.WithMsgf("unexpected resources %v for %s", v, k)
		}
		res[k] = *v[0]
	}

	return res, nil
}

// UpdateUserBundle ...
func (m *Registration) UpdateUserBundle(ctx context.Context, input *tpl.Bundle) error {
	now := util.UnixMS()
	qs := fmt.Sprintf(`
	service(func: eq(serviceUK, "%s")) {
		s as uid
	}
	user(func: eq(userUK, "%s")) {
		u as uid
	}
	`, util.SubjectUK(*input.Provider), util.SubjectUK(*input.OTID))

	create := &Nquads{
		UKkey: "bundleUK",
		UKval: util.UserBundleUK(*input.Provider, input.BundleID),
		Type:  "UserRegistryBundle",
		KV: map[string]interface{}{
			"createdAt":    now,
			"updatedAt":    now,
			"bundleId":     input.BundleID,
			"extension":    input.Extension,
			"provider":     "uid(s)",
			"userRegistry": "uid(u)",
		},
	}

	update := &Nquads{
		KV: map[string]interface{}{
			"updatedAt": now,
			"extension": input.Extension,
		},
	}

	return m.Model.CreateOrUpdate(ctx, qs, create, update)
}

type getUserBundlesPayload struct {
	Status  int `json:"status"`
	Bundles []*struct {
		BundleID  string `json:"bundleId"`
		Extension string `json:"extension"`
		Provider  *struct {
			SubjectID   string `json:"subjectId"`
			SubjectType string `json:"subjectType"`
		} `json:"provider"`
	} `json:"bundles"`
}

// GetUserBundles ...
func (m *Registration) GetUserBundles(ctx context.Context, input *tpl.OTIDURL) (*tpl.RegistryPayload, error) {
	if conf.SubjectType(input.OTID) != 1 {
		return nil, gear.ErrBadRequest.WithMsgf("subject should be one of user types, but got %s", input.OTID.Type())
	}
	uk := util.SubjectUK(input.OTID)
	vars := map[string]string{"$uk": uk}
	q := `query q($uk: string) {
		result(func: eq(userUK, $uk)) {
			status
			bundles: <~userRegistry> {
				bundleId
				extension
				provider {
					subjectId
					subjectType
				}
			}
		}
	}
	`

	data := &getUserBundlesPayload{}
	err := m.Model.Get(ctx, q, vars, data)
	if err != nil {
		return nil, err
	}
	bundles := make([]tpl.Bundle, 0, len(data.Bundles))
	for _, b := range data.Bundles {
		provider := conf.OT.TrustDomain.NewOTID(b.Provider.SubjectType, b.Provider.SubjectID)
		bundles = append(bundles, tpl.Bundle{
			Provider:  &provider,
			BundleID:  b.BundleID,
			Extension: b.Extension,
		})
	}

	return &tpl.RegistryPayload{
		OTID:    &input.OTID,
		Status:  data.Status,
		Bundles: &bundles,
	}, nil
}

type getServicePermissionsPayload struct {
	Status      int               `json:"status"`
	Permissions []*tpl.Permission `json:"permissions"`
}

// GetServicePermissions ...
func (m *Registration) GetServicePermissions(ctx context.Context, input *tpl.OTIDURL) (*tpl.RegistryPayload, error) {
	if conf.SubjectType(input.OTID) != 2 {
		return nil, gear.ErrBadRequest.WithMsgf("subject should be one of service types, but got %s", input.OTID.Type())
	}
	uk := util.SubjectUK(input.OTID)
	vars := map[string]string{"$uk": uk}
	q := `query q($uk: string) {
		result(func: eq(serviceUK, $uk)) {
			status
			permissions: <~serviceRegistry> {
				resource
				operations
				extensions
			}
		}
	}
	`

	data := &getServicePermissionsPayload{}
	err := m.Model.Get(ctx, q, vars, data)
	if err != nil {
		return nil, err
	}
	ps := make([]tpl.Permission, 0, len(data.Permissions))
	for _, b := range data.Permissions {
		ps = append(ps, *b)
	}

	return &tpl.RegistryPayload{
		OTID:        &input.OTID,
		Status:      data.Status,
		Permissions: &ps,
	}, nil
}
