package conf

import (
	"context"
	"errors"
	"os"

	"github.com/open-trust/ot-auth/src/util"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

// AppName 服务名
var AppName = "OT-Auth"

// AppVersion 服务版本
var AppVersion = "unknown"

// BuildTime 镜像生成时间
var BuildTime = "unknown"

// GitSHA1 镜像对应 git commit id
var GitSHA1 = "unknown"

// AppEnv ...
var AppEnv = os.Getenv("APP_ENV")

// GlobalContext ...
var GlobalContext = gear.ContextWithSignal(context.Background())

func init() {
	p := &Config
	util.ReadConfig(p)
	err := p.Validate()
	if err != nil {
		panic(err)
	}
	if AppEnv == "" {
		AppEnv = "development"
	}

	if err = initOT(p); err != nil {
		panic(err)
	}
}

// Config ...
var Config ConfigTpl

// OT ...
var OT *ot

func initOT(cfg *ConfigTpl) error {
	OT = &ot{
		OTID:        cfg.OpenTrust.OTID,
		TrustDomain: cfg.OpenTrust.OTID.TrustDomain(),
	}
	var err error
	OT.PrivateKeys, err = otgo.ParseKeys(cfg.OpenTrust.PrivateKeys...)
	if err != nil {
		return err
	}
	OT.PublicKeys = otgo.LookupPublicKeys(OT.PrivateKeys)
	if len(OT.PublicKeys.Keys) == 0 {
		return errors.New("no public keys found")
	}
	OT.Holder, err = otgo.NewHolder(GlobalContext, cfg.OpenTrust.OTID)
	if err != nil {
		return err
	}
	OT.Holder.SetKeys(*OT.PrivateKeys)
	OT.Verifier, err = otgo.NewVerifier(GlobalContext, cfg.OpenTrust.OTID, false)
	if err != nil {
		return err
	}
	OT.Verifier.SetKeys(*OT.PublicKeys)
	return nil
}

// Logger logger config
type Logger struct {
	Level string `json:"level" yaml:"level"`
}

// Dgraph ...
type Dgraph struct {
	Endpoint      string `json:"graphql_endpoint" yaml:"graphql_endpoint"`
	AdminEndpoint string `json:"admin_endpoint" yaml:"admin_endpoint"`
}

// OpenTrust ...
type OpenTrust struct {
	OTID            otgo.OTID `json:"otid" yaml:"otid"`
	UserTypes       []string  `json:"user_types" yaml:"user_types"`
	ServiceTypes    []string  `json:"service_types" yaml:"service_types"`
	PrivateKeys     []string  `json:"private_keys" yaml:"private_keys"`
	KeysRefreshHint int       `json:"keys_refresh_hint" yaml:"keys_refresh_hint"`
}

// ConfigTpl ...
type ConfigTpl struct {
	SrvAddr          string    `json:"addr" yaml:"addr"`
	CertFile         string    `json:"cert_file" yaml:"cert_file"`
	KeyFile          string    `json:"key_file" yaml:"key_file"`
	TrustedProxy     bool      `json:"trusted_proxy" yaml:"trusted_proxy"`
	Logger           Logger    `json:"logger" yaml:"logger"`
	Dgraph           Dgraph    `json:"dgraph" yaml:"dgraph"`
	ServiceEndpoints []string  `json:"service_endpoints" yaml:"service_endpoints"`
	OpenTrust        OpenTrust `json:"open_trust" yaml:"open_trust"`
}

// Validate 用于完成基本的配置验证和初始化工作。业务相关的配置验证建议放到相关代码中实现，如 mysql 的配置。
func (c *ConfigTpl) Validate() error {
	err := c.OpenTrust.OTID.Validate()
	if err != nil {
		return err
	}
	return nil
}

// OT ...
type ot struct {
	TrustDomain otgo.TrustDomain
	OTID        otgo.OTID
	Holder      *otgo.Holder
	Verifier    *otgo.Verifier
	PrivateKeys *otgo.Keys
	PublicKeys  *otgo.Keys
}

func (o *ot) NewVerifier(aud otgo.OTID) (*otgo.Verifier, error) {
	if !aud.MemberOf(o.TrustDomain) {
		return nil, errors.New("aud is not a member of trust domain")
	}
	verifier, err := otgo.NewVerifier(GlobalContext, aud, false)
	if err != nil {
		return nil, err
	}
	verifier.SetKeys(*OT.PublicKeys)
	return verifier, nil
}

// SubjectType validate OTID' type, returns: 1 - user class, 2 - service class, 0 - unknown
func SubjectType(otid otgo.OTID) int {
	t := otid.Type()
	filter := func(s string) bool { return s == t }
	if util.StringsHas(Config.OpenTrust.UserTypes, filter) {
		return 1
	} else if util.StringsHas(Config.OpenTrust.ServiceTypes, filter) {
		return 2
	}
	return 0
}

// AppInfo ...
func AppInfo() map[string]interface{} {
	return map[string]interface{}{
		"name":      AppName,
		"version":   AppVersion,
		"env":       AppEnv,
		"buildTime": BuildTime,
		"gitSHA1":   GitSHA1,
	}
}
