package api

import (
	"github.com/open-trust/ot-auth/src/bll"
	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/middleware"
	"github.com/open-trust/ot-auth/src/service/ac"
	"github.com/open-trust/ot-auth/src/tpl"
	"github.com/open-trust/ot-auth/src/util"
	"github.com/teambition/gear"
)

// Registration ..
type Registration struct {
	blls *bll.Blls
}

// Add ..
func (a *Registration) Add(ctx *gear.Context) error {
	// 读取并验证请求数据
	input := &tpl.AddRegistrationInput{}
	if err := ctx.ParseBody(input); err != nil {
		return err
	}

	// 获取经过验证的请求主体的 OTVID
	vid, err := middleware.VidFromCtx(ctx)
	if err != nil {
		return err
	}

	// 查询请求主体的请求权限
	ps, err := ac.FindPermissions(ctx, vid.ID, ac.ResRegistration, ac.OpCreate)
	if err != nil {
		return err
	}

	// 根据 Permission 扩展信息（如果有）进一步验证权限
	// 检查请求主体是否能创建请求数据中的目标 subject
	sp := ps.FindExtensionValues(ac.EkCreateRegistration)
	subject := input.OTID.Subject()
	if !util.StringsHas(sp, func(pattern string) bool {
		return ac.MatchPattern(subject, pattern)
	}) {
		return gear.ErrForbidden.WithMsgf("create registration %s not allowed", subject)
	}

	res, err := a.blls.Registration.Add(ctx, input)
	if err != nil {
		return err
	}

	return ctx.OkJSON(res)
}

// Get ..
func (a *Registration) Get(ctx *gear.Context) error {
	// 读取并验证请求数据
	input := &tpl.OTIDURL{}
	if err := ctx.ParseURL(input); err != nil {
		return err
	}
	// 获取经过验证的请求主体的 OTVID
	vid, err := middleware.VidFromCtx(ctx)
	if err != nil {
		return err
	}

	// 查询请求主体的请求权限
	_, err = ac.FindPermissions(ctx, vid.ID, ac.ResRegistration, ac.OpGet)
	if err != nil {
		return err
	}
	res, err := a.blls.Registration.Get(ctx, input)
	if err != nil {
		return err
	}

	return ctx.OkJSON(res)
}

// List ..
func (a *Registration) List(ctx *gear.Context) error {
	return nil
}

// GetUserBundles ..
func (a *Registration) GetUserBundles(ctx *gear.Context) error {
	// 读取并验证请求数据
	input := &tpl.OTIDURL{}
	if err := ctx.ParseURL(input); err != nil {
		return err
	}
	if conf.SubjectType(input.OTID) != 1 {
		return gear.ErrBadRequest.WithMsgf("only user types have bundles")
	}
	// 获取经过验证的请求主体的 OTVID
	vid, err := middleware.VidFromCtx(ctx)
	if err != nil {
		return err
	}
	// 请求主体可以查询自己的 bundles，非自己的则需要另外验证权限
	if !vid.ID.Equal(input.OTID) {
		// 查询请求主体的请求权限
		ps, err := ac.FindPermissions(ctx, vid.ID, ac.ResRegistrationBundle, ac.OpGet)
		if err != nil {
			return err
		}
		// 根据 Permission 扩展信息（如果有）进一步验证权限
		// 检查请求主体是否能查询目标 subject 的 bundles
		sp := ps.FindExtensionValues(ac.EkGetRegistrationBundles)
		subject := input.OTID.Subject()
		if !util.StringsHas(sp, func(pattern string) bool {
			return ac.MatchPattern(subject, pattern)
		}) {
			return gear.ErrForbidden.WithMsgf("get registration %s's bundles not allowed", subject)
		}
	}

	res, err := a.blls.Registration.GetUserBundles(ctx, input)
	if err != nil {
		return err
	}

	return ctx.OkJSON(res)
}

// GetServicePermissions ..
func (a *Registration) GetServicePermissions(ctx *gear.Context) error {
	// 读取并验证请求数据
	input := &tpl.OTIDURL{}
	if err := ctx.ParseURL(input); err != nil {
		return err
	}
	if conf.SubjectType(input.OTID) != 2 {
		return gear.ErrBadRequest.WithMsgf("only service types have permissions")
	}
	// 获取经过验证的请求主体的 OTVID
	vid, err := middleware.VidFromCtx(ctx)
	if err != nil {
		return err
	}
	// 请求主体可以查询自己的 permissions，非自己的则需要另外验证权限
	if !vid.ID.Equal(input.OTID) {
		// 查询请求主体的请求权限
		ps, err := ac.FindPermissions(ctx, vid.ID, ac.ResRegistrationPermission, ac.OpGet)
		if err != nil {
			return err
		}
		// 根据 Permission 扩展信息（如果有）进一步验证权限
		// 检查请求主体是否能查询目标 subject 的 permissions
		sp := ps.FindExtensionValues("getRegistrationPermissionsPattern:")
		subject := input.OTID.Subject()
		if len(sp) > 0 && !util.StringsHas(sp, func(pattern string) bool {
			return ac.MatchPattern(subject, pattern)
		}) {
			return gear.ErrForbidden.WithMsgf("get registration %s's permissions not allowed", subject)
		}
	}

	res, err := a.blls.Registration.GetServicePermissions(ctx, input)
	if err != nil {
		return err
	}

	return ctx.OkJSON(res)
}
