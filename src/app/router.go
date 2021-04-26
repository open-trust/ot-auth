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
	router.Get("/healthz", apis.Healthz.Get) // deprecated, https://kubernetes.io/docs/reference/using-api/health-checks/
	router.Get("/livez", apis.Healthz.Get)
	router.Get("/readyz", apis.Healthz.Get)
	router.Get("/.well-known/open-trust-configuration", apis.WellKnown.OpenTrustConfiguration)

	router.Get("/graphql", middleware.Verify, apis.GraphQL.All)
	router.Post("/graphql", middleware.Verify, apis.GraphQL.All)

	routerV1 := gear.NewRouter(gear.RouterOptions{
		Root: "/v1",
	})

	routerV1.Get("/", getVersion)

	routerV1.Post("/sign", apis.OTVID.Sign) // 自签发 OTVID，在 API 内验证
	routerV1.Post("/verify", middleware.Verify, apis.OTVID.Verify)

	routerV1.Post("/federation", middleware.Verify, nil)
	routerV1.Get("/federation/:domain", middleware.Verify, nil)
	routerV1.Patch("/federation/:domain", middleware.Verify, nil)
	routerV1.Delete("/federation/:domain", middleware.Verify, nil)

	routerV1.Post("/registries", middleware.Verify, apis.Registration.Add)
	routerV1.Get("/registries", middleware.Verify, apis.Registration.List)
	routerV1.Get("/registries/:otid", middleware.Verify, apis.Registration.Get)
	routerV1.Patch("/registries/:otid", middleware.Verify, nil)
	routerV1.Delete("/registries/:otid", middleware.Verify, nil)
	routerV1.Get("/registries/:otid/bundles", middleware.Verify, apis.Registration.GetUserBundles)
	routerV1.Delete("/registries/:otid/bundles", middleware.Verify, nil)

	routerV1.Get("/registries/:otid/permissions", middleware.Verify, apis.Registration.GetServicePermissions)
	routerV1.Post("/registries/:otid/permissions", middleware.Verify, nil)
	routerV1.Delete("/registries/:otid/permissions", middleware.Verify, nil)

	routerV1.Post("/bundles", middleware.Verify, apis.Registration.UpdateUsersBundle)

	return []*gear.Router{router, routerV1}
}
