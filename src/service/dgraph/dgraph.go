package dgraph

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/util"
)

func init() {
	util.DigProvide(NewDgraph)
	userAgent = fmt.Sprintf("Go/%v %s/%s (Dgraph client)", runtime.Version(), conf.AppName, conf.AppVersion)
}

var userAgent string

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   3 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// Dgraph ...
type Dgraph struct {
	*Client
}

// NewDgraph ...
func NewDgraph() *Dgraph {
	cli := NewClient(&http.Client{
		Transport: tr,
		Timeout:   time.Second * 5,
	}, conf.Config.Dgraph.Endpoint, func(req *http.Request) {
		req.Header.Set("User-Agent", userAgent)
	})
	return &Dgraph{cli}
}
