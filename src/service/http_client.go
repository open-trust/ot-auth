package service

import (
	"fmt"
	"runtime"

	"github.com/open-trust/ot-auth/src/conf"
	otgo "github.com/open-trust/ot-go-lib"
)

func init() {
	HTTPClient = otgo.DefaultHTTPClient.WithUA(fmt.Sprintf("Go/%v %s/%s (Dgraph client)", runtime.Version(), conf.AppName, conf.AppVersion))
}

// HTTPClient ...
var HTTPClient *otgo.HTTPClient
