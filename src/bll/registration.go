package bll

import (
	"context"

	"github.com/open-trust/ot-auth/src/model"
	"github.com/open-trust/ot-auth/src/tpl"
	otgo "github.com/open-trust/ot-go-lib"
)

// Registration ...
type Registration struct {
	ms *model.Models
}

// Add ...
func (b *Registration) Add(ctx context.Context, input *tpl.AddRegistrationInput) (*tpl.SuccessResponseType, error) {
	res, err := b.ms.Registration.Add(ctx, input)
	if err != nil {
		return nil, err
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
