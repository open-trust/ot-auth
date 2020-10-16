package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/open-trust/ot-auth/src/api"
	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/logging"
)

var help = flag.Bool("help", false, "show help info")
var version = flag.Bool("version", false, "show version info")

func main() {
	flag.Parse()
	appInfo := conf.AppInfo()
	if *help || *version {
		data, _ := json.Marshal(appInfo)
		fmt.Println(string(data))
		os.Exit(0)
	}

	if len(conf.Config.SrvAddr) == 0 {
		conf.Config.SrvAddr = ":8080"
	}

	app := api.NewApp()
	prefix := "http://"
	if conf.Config.CertFile != "" && conf.Config.KeyFile != "" {
		prefix = "https://"
	}

	logging.Logger.Info(logging.SrvLog("start on %s", prefix+conf.Config.SrvAddr).With(appInfo))
	logging.Errf("%s closed %v", conf.AppName, app.ListenWithContext(
		conf.GlobalContext, conf.Config.SrvAddr, conf.Config.CertFile, conf.Config.KeyFile))
}
