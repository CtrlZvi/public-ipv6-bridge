package main

import (
	"github.com/CtrlZvi/public-ipv6-bridge/bridge"
	"github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/network"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	pluginName = "public-ipv6-bridge"
)

var (
	debug = kingpin.Flag("debug", "enable debug logging").Default("false").Bool()
)

func main() {
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	d := bridge.NewDriver()
	h := network.NewHandler(d)
	h.ServeUnix("", pluginName)
}
