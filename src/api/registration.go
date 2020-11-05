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
	input := &tpl.AddRegistriesInput{}
	if err := ctx.ParseBody(input); err != nil {
		return err
	}

	// 获取经过验证的请求主体的 OTVID
	vid, err := middleware.VidFromCtx(ctx)
	if err != nil {
		return err
	}

	// 查询请求主体的请求权限
	ps, err := ac.FindPermissions(ctx, vid.ID, ac.ResRegistry, ac.OpCreate)
	if err != nil {
		return err
	}

	// 根据 Permission 扩展信息（如果有）进一步验证权限
	// 检查请求主体是否能创建请求数据中的目标 subject
	sp := ps.FindExtensionValues(ac.EkCreateRegistry)

	if input.RegistryInput != nil {
		subject := input.RegistryInput.OTID.String()
		if !util.StringsHas(sp, func(pattern string) bool {
			return ac.MatchPattern(subject, pattern)
		}) {
			return gear.ErrForbidden.WithMsgf("create registry %s not allowed", subject)
		}
	} else {
		for _, ele := range input.Registries {
			subject := ele.OTID.Subject()
			if !util.StringsHas(sp, func(pattern string) bool {
				return ac.MatchPattern(subject, pattern)
			}) {
				return gear.ErrForbidden.WithMsgf("create registry %s not allowed", subject)
			}
		}
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
	_, err = ac.FindPermissions(ctx, vid.ID, ac.ResRegistry, ac.OpGet)
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
		ps, err := ac.FindPermissions(ctx, vid.ID, ac.ResRegistryBundle, ac.OpGet)
		if err != nil {
			return err
		}
		// 根据 Permission 扩展信息（如果有）进一步验证权限
		// 检查请求主体是否能查询目标 subject 的 bundles
		sp := ps.FindExtensionValues(ac.EkGetRegistryBundles)
		subject := input.OTID.Subject()
		if !util.StringsHas(sp, func(pattern string) bool {
			return ac.MatchPattern(subject, pattern)
		}) {
			return gear.ErrForbidden.WithMsgf("get registry %s's bundles not allowed", subject)
		}
	}

	res, err := a.blls.Registration.GetUserBundles(ctx, input)
	if err != nil {
		return err
	}

	return ctx.OkJSON(res)
}

// UpdateUsersBundle ..
func (a *Registration) UpdateUsersBundle(ctx *gear.Context) error {
	// 读取并验证请求数据
	input := &tpl.UpdateUsersBundleInput{}
	if err := ctx.ParseBody(input); err != nil {
		return err
	}
	// 获取经过验证的请求主体的 OTVID
	vid, err := middleware.VidFromCtx(ctx)
	if err != nil {
		return err
	}
	if input.Provider == nil {
		input.Provider = &vid.ID
	}

	if conf.SubjectType(*input.Provider) != 2 {
		return gear.ErrForbidden.WithMsgf("provider should be one of service, but got %", input.Provider.Type())
	}
	// 请求主体可以创建、更新自己领域的 bundles，非自己领域的则需要另外验证权限
	if !input.Provider.Equal(vid.ID) {
		// 查询请求主体的请求权限
		ps, err := ac.FindPermissions(ctx, vid.ID, ac.ResRegistryBundle, ac.OpCreate)
		if err != nil {
			return err
		}
		// 根据 Permission 扩展信息（如果有）进一步验证权限
		// 检查请求主体是否能查询目标 subject 的 bundles
		sp := ps.FindExtensionValues(ac.EkCreateRegistryBundle)
		provider := input.Provider.Subject()
		if !util.StringsHas(sp, func(pattern string) bool {
			return ac.MatchPattern(provider, pattern)
		}) {
			return gear.ErrForbidden.WithMsgf("create registry %s's bundles not allowed", provider)
		}
	}

	res, err := a.blls.Registration.UpdateUsersBundle(ctx, input)
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
		ps, err := ac.FindPermissions(ctx, vid.ID, ac.ResRegistryPermission, ac.OpGet)
		if err != nil {
			return err
		}
		// 根据 Permission 扩展信息（如果有）进一步验证权限
		// 检查请求主体是否能查询目标 subject 的 permissions
		sp := ps.FindExtensionValues(ac.EkGetRegistryPermissions)
		subject := input.OTID.Subject()
		if len(sp) > 0 && !util.StringsHas(sp, func(pattern string) bool {
			return ac.MatchPattern(subject, pattern)
		}) {
			return gear.ErrForbidden.WithMsgf("get registry %s's permissions not allowed", subject)
		}
	}

	res, err := a.blls.Registration.GetServicePermissions(ctx, input)
	if err != nil {
		return err
	}

	return ctx.OkJSON(res)
}
