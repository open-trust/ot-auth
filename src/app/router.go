package app

import (
	"github.com/teambition/gear"

	"github.com/open-trust/ot-auth/src/api"
	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/middleware"
	"github.com/open-trust/ot-auth/src/util"
)

func init() {
	util.DigProvide(NewRouters)
}

func getVersion(ctx *gear.Context) error {
	return ctx.OkJSON(conf.AppInfo())
}

// NewRouters ...
func NewRouters(apis *api.APIs) []*gear.Router {

	router := gear.NewRouter()
	router.Get("/", getVersion)
	router.Get("/version", getVersion)
	router.Get("/healthz", apis.Healthz.Get)
	router.Get("/.well-known/open-trust-configuration", apis.WellKnown.OpenTrustConfiguration)

	router.Get("/graphql", middleware.Verify, apis.GraphQL.All)
	router.Post("/graphql", middleware.Verify, apis.GraphQL.All)

	routerV1 := gear.NewRouter(gear.RouterOptions{
		Root: "/v1",
	})

	routerV1.Get("/", apis.WellKnown.ServiceEndpoints)

	routerV1.Post("/sign", apis.OTVID.Sign) // 自签发 OTVID，在 API 内验证
	routerV1.Post("/verify", middleware.Verify, apis.OTVID.Verify)

	routerV1.Post("/federations", middleware.Verify, nil)
	routerV1.Get("/federations/:domain", middleware.Verify, nil)
	routerV1.Patch("/federations/:domain", middleware.Verify, nil)
	routerV1.Delete("/federations/:domain", middleware.Verify, nil)

	routerV1.Post("/registrations", middleware.Verify, apis.Registration.Add)
	routerV1.Get("/registrations", middleware.Verify, apis.Registration.List)
	routerV1.Get("/registrations/:otid", middleware.Verify, apis.Registration.Get)
	routerV1.Patch("/registrations/:otid", middleware.Verify, nil)
	routerV1.Delete("/registrations/:otid", middleware.Verify, nil)

	routerV1.Get("/registrations/:otid/bundles", middleware.Verify, apis.Registration.GetUserBundles)
	routerV1.Post("/registrations/:otid/bundles", middleware.Verify, nil)
	routerV1.Delete("/registrations/:otid/bundles", middleware.Verify, nil)

	routerV1.Get("/registrations/:otid/permissions", middleware.Verify, apis.Registration.GetServicePermissions)
	routerV1.Post("/registrations/:otid/permissions", middleware.Verify, nil)
	routerV1.Delete("/registrations/:otid/permissions", middleware.Verify, nil)

	return []*gear.Router{router, routerV1}
}
