package bll

import (
	"context"
	"fmt"
	"net/http"

	"github.com/open-trust/ot-auth/src/model"
	"github.com/open-trust/ot-auth/src/tpl"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

// Registration ...
type Registration struct {
	ms *model.Models
}

// Add ...
func (b *Registration) Add(ctx context.Context, input *tpl.AddRegistriesInput) (*tpl.SuccessResponseType, error) {
	if input.RegistryInput != nil {
		one, err := b.ms.Registration.Add(ctx, input.RegistryInput)
		if err != nil {
			return nil, err
		}
		return &tpl.SuccessResponseType{Result: one}, nil
	}
	res := make([]*tpl.RegistryPayload, 0, len(input.Registries))
	for _, ele := range input.Registries {
		one, err := b.ms.Registration.Add(ctx, ele)
		if err == nil {
			res = append(res, one)
		} else if e, ok := err.(gear.HTTPError); ok && e.Status() == http.StatusConflict {
			res = append(res, &tpl.RegistryPayload{
				OTID:        &ele.OTID,
				SubjectType: ele.SubjectType,
				SubjectID:   ele.SubjectID,
			})
		}
	}
	return &tpl.SuccessResponseType{Result: res}, nil
}

// Get ...
func (b *Registration) Get(ctx context.Context, input *tpl.OTIDURL) (*tpl.SuccessResponseType, error) {
	res, err := b.ms.Registration.Get(ctx, input)
	if err != nil {
		return nil, err
	}
	return &tpl.SuccessResponseType{Result: res}, nil
}

// CheckStatus ...
func (b *Registration) CheckStatus(ctx context.Context, otid otgo.OTID, releaseID string) (bool, error) {
	info, err := b.ms.Registration.GetVerificationInfo(ctx, otid, false, false)
	if err != nil {
		return false, err
	}
	if info.Status < 0 {
		return false, nil
	}
	if releaseID != "" && releaseID != info.ReleaseID {
		return false, nil
	}
	return true, nil
}

// List ...
func (b *Registration) List(ctx context.Context) (*tpl.SuccessResponseType, error) {
	return nil, nil
}

// UpdateUsersBundle ...
func (b *Registration) UpdateUsersBundle(ctx context.Context, input *tpl.UpdateUsersBundleInput) (*tpl.SuccessResponseType, error) {
	infoMap := make(map[string]otgo.OTID)
	infoMap["provider"] = *input.Provider
	for i, ele := range input.Bundles {
		infoMap[fmt.Sprintf("q%d", i)] = ele.OTID
	}
	_, err := b.ms.Registration.AcquireInfos(ctx, infoMap)
	if err != nil {
		return nil, err
	}

	res := make([]tpl.Bundle, 0, len(input.Bundles))
	for _, ele := range input.Bundles {
		one := tpl.Bundle{
			Provider:  input.Provider,
			OTID:      &ele.OTID,
			BundleID:  ele.BundleID,
			Extension: ele.Extension,
		}
		if err = b.ms.Registration.UpdateUserBundle(ctx, &one); err == nil {
			res = append(res, one)
		}
	}

	return &tpl.SuccessResponseType{Result: res}, nil
}

// GetUserBundles ...
func (b *Registration) GetUserBundles(ctx context.Context, input *tpl.OTIDURL) (*tpl.SuccessResponseType, error) {
	res, err := b.ms.Registration.GetUserBundles(ctx, input)
	if err != nil {
		return nil, err
	}
	return &tpl.SuccessResponseType{Result: res}, nil
}

// GetServicePermissions ...
func (b *Registration) GetServicePermissions(ctx context.Context, input *tpl.OTIDURL) (*tpl.SuccessResponseType, error) {
	res, err := b.ms.Registration.GetServicePermissions(ctx, input)
	if err != nil {
		return nil, err
	}
	return &tpl.SuccessResponseType{Result: res}, nil
}
