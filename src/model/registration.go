package model

import (
	"context"
	"fmt"
	"time"

	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/service/dgraph"
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
func (m *Registration) Add(ctx context.Context, input *tpl.AddRegistrationInput) (*tpl.RegistrationPayload, error) {
	switch conf.SubjectType(input.OTID) {
	case 1:
		return m.addUser(ctx, input)
	case 2:
		return m.addService(ctx, input)
	}
	return nil, fmt.Errorf("unknow subject type")
}

func (m *Registration) addUser(ctx context.Context, input *tpl.AddRegistrationInput) (*tpl.RegistrationPayload, error) {
	now := time.Now().Truncate(time.Millisecond)
	data := dgraph.AddUserRegistryInput{
		CreatedAt:     now,
		UpdatedAt:     now,
		SubjectID:     input.SubjectID,
		SubjectType:   input.SubjectType,
		Description:   input.Description,
		Keys:          input.Keys,
		KeysUpdatedAt: now,
		Status:        0,
		ReleaseID:     util.ReleaseID(),
		Uk:            util.SubjectUK(input.OTID),
	}
	payload, err := m.Model.AddRegistrationForUser(ctx, data)
	if err != nil {
		return nil, err
	}
	if l := len(payload.AddUserRegistry.UserRegistry); l != 1 {
		return nil, gear.ErrInternalServerError.WithMsgf("Dgraph AddRegistrationForUser returned unknown result: %#v", payload)
	}
	doc := payload.AddUserRegistry.UserRegistry[0]
	res := &tpl.RegistrationPayload{
		OTID:          input.OTID,
		SubjectID:     input.OTID.ID(),
		SubjectType:   input.OTID.Type(),
		Description:   &data.Description,
		Keys:          &data.Keys,
		CreatedAt:     &doc.CreatedAt,
		UpdatedAt:     &doc.UpdatedAt,
		KeysUpdatedAt: &doc.KeysUpdatedAt,
		Status:        data.Status,
	}
	return res, nil
}

func (m *Registration) addService(ctx context.Context, input *tpl.AddRegistrationInput) (*tpl.RegistrationPayload, error) {
	now := time.Now().Truncate(time.Millisecond)
	data := dgraph.AddServiceRegistryInput{
		CreatedAt:        now,
		UpdatedAt:        now,
		SubjectID:        input.SubjectID,
		SubjectType:      input.SubjectType,
		Description:      input.Description,
		Keys:             input.Keys,
		KeysUpdatedAt:    now,
		Status:           0,
		ServiceEndpoints: input.ServiceEndpoints,
		Uk:               util.SubjectUK(input.OTID),
	}
	payload, err := m.Model.AddRegistrationForService(ctx, data)
	if err != nil {
		return nil, err
	}
	if l := len(payload.AddServiceRegistry.ServiceRegistry); l != 1 {
		return nil, gear.ErrInternalServerError.WithMsgf("Dgraph AddRegistrationForService returned unknown result: %#v", payload)
	}
	doc := payload.AddServiceRegistry.ServiceRegistry[0]
	res := &tpl.RegistrationPayload{
		OTID:             input.OTID,
		SubjectID:        input.OTID.ID(),
		SubjectType:      input.OTID.Type(),
		Description:      &data.Description,
		Keys:             &data.Keys,
		CreatedAt:        &doc.CreatedAt,
		UpdatedAt:        &doc.UpdatedAt,
		KeysUpdatedAt:    &doc.KeysUpdatedAt,
		Status:           data.Status,
		ServiceEndpoints: &input.ServiceEndpoints,
	}
	return res, nil
}

// Get ...
func (m *Registration) Get(ctx context.Context, input *tpl.OTIDURL) (*tpl.RegistrationPayload, error) {
	switch conf.SubjectType(input.OTID) {
	case 1:
		return m.getUser(ctx, input)
	case 2:
		return m.getService(ctx, input)
	}
	return nil, fmt.Errorf("unknow subject type")
}

func (m *Registration) getUser(ctx context.Context, input *tpl.OTIDURL) (*tpl.RegistrationPayload, error) {
	payload, err := m.Model.GetRegistrationForUser(ctx, util.SubjectUK(input.OTID))
	if err != nil {
		return nil, err
	}
	doc := payload.GetUserRegistry
	if doc == nil {
		return nil, gear.ErrNotFound.WithMsgf("%s not found", input.OTID.String())
	}
	res := &tpl.RegistrationPayload{
		OTID:          input.OTID,
		SubjectID:     doc.SubjectID,
		SubjectType:   doc.SubjectType,
		Description:   &doc.Description,
		Keys:          &doc.Keys,
		KeysUpdatedAt: &doc.KeysUpdatedAt,
		Status:        doc.Status,
		CreatedAt:     &doc.CreatedAt,
		UpdatedAt:     &doc.UpdatedAt,
	}
	return res, nil
}

func (m *Registration) getService(ctx context.Context, input *tpl.OTIDURL) (*tpl.RegistrationPayload, error) {
	payload, err := m.Model.GetRegistrationForService(ctx, util.SubjectUK(input.OTID))
	if err != nil {
		return nil, err
	}
	doc := payload.GetServiceRegistry
	if doc == nil {
		return nil, gear.ErrNotFound.WithMsgf("%s not found", input.OTID.String())
	}
	res := &tpl.RegistrationPayload{
		OTID:             input.OTID,
		SubjectID:        doc.SubjectID,
		SubjectType:      doc.SubjectType,
		Description:      &doc.Description,
		Keys:             &doc.Keys,
		KeysUpdatedAt:    &doc.KeysUpdatedAt,
		Status:           doc.Status,
		CreatedAt:        &doc.CreatedAt,
		UpdatedAt:        &doc.UpdatedAt,
		ServiceEndpoints: &doc.ServiceEndpoints,
	}
	return res, nil
}

// GetVerificationInfo ...
func (m *Registration) GetVerificationInfo(ctx context.Context, otid otgo.OTID, includeKeys, includeEndpoints bool) (*VerificationInfo, error) {
	switch conf.SubjectType(otid) {
	case 1:
		return m.getUserVerificationInfo(ctx, otid, includeKeys)
	case 2:
		return m.getServiceVerificationInfo(ctx, otid, includeKeys, includeEndpoints)
	}
	return nil, fmt.Errorf("unknow subject type")
}

func (m *Registration) getUserVerificationInfo(ctx context.Context, otid otgo.OTID, includeKeys bool) (*VerificationInfo, error) {
	payload, err := m.Model.GetUserVerificationInfo(ctx, util.SubjectUK(otid), includeKeys)
	if err != nil {
		return nil, err
	}
	doc := payload.GetUserRegistry
	if doc == nil {
		return nil, gear.ErrNotFound.WithMsgf("%s not found", otid.String())
	}
	return &VerificationInfo{ID: otid, Status: doc.Status, ReleaseID: doc.ReleaseID, Keys: doc.Keys}, nil
}

func (m *Registration) getServiceVerificationInfo(ctx context.Context, otid otgo.OTID, includeKeys, includeEndpoints bool) (*VerificationInfo, error) {
	payload, err := m.Model.GetServiceVerificationInfo(ctx, util.SubjectUK(otid), includeKeys, includeEndpoints)
	if err != nil {
		return nil, err
	}
	doc := payload.GetServiceRegistry
	if doc == nil {
		return nil, gear.ErrNotFound.WithMsgf("%s not found", otid.String())
	}
	return &VerificationInfo{ID: otid, Status: doc.Status, Keys: doc.Keys, ServiceEndpoints: doc.ServiceEndpoints}, nil
}

// GetUserBundles ...
func (m *Registration) GetUserBundles(ctx context.Context, input *tpl.OTIDURL) (*tpl.RegistrationPayload, error) {
	payload, err := m.Model.GetUserBundles(ctx, util.SubjectUK(input.OTID))
	if err != nil {
		return nil, err
	}
	doc := payload.GetUserRegistry
	if doc == nil {
		return nil, gear.ErrNotFound.WithMsgf("%s not found", input.OTID.String())
	}
	bundles := make([]tpl.Bundle, 0, len(doc.Bundles))
	for _, b := range doc.Bundles {
		bundles = append(bundles, tpl.Bundle{
			Provider: conf.OT.TrustDomain.NewOTID(b.Provider.SubjectType, b.Provider.SubjectID),
			BundleID: b.BundleID,
		})
	}
	res := &tpl.RegistrationPayload{
		OTID:    input.OTID,
		Status:  doc.Status,
		Bundles: &bundles,
	}
	return res, nil
}

// GetServicePermissions ...
func (m *Registration) GetServicePermissions(ctx context.Context, input *tpl.OTIDURL) (*tpl.RegistrationPayload, error) {
	payload, err := m.Model.GetServicePermissions(ctx, util.SubjectUK(input.OTID))
	if err != nil {
		return nil, err
	}
	doc := payload.GetServiceRegistry
	if doc == nil {
		return nil, gear.ErrNotFound.WithMsgf("%s not found", input.OTID.String())
	}
	permission := make([]tpl.Permission, 0, len(doc.Permissions))
	for _, p := range doc.Permissions {
		permission = append(permission, tpl.Permission{
			Resource:   p.Resource,
			Operations: p.Operations,
			Extensions: p.Extensions,
		})
	}
	res := &tpl.RegistrationPayload{
		OTID:        input.OTID,
		Status:      doc.Status,
		Permissions: &permission,
	}
	return res, nil
}
